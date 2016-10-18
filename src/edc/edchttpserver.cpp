// Copyright (c) 2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edchttpserver.h"

#include "chainparamsbase.h"
#include "compat.h"
#include "edcutil.h"
#include "edcnetbase.h"
#include "rpc/protocol.h" // For HTTP status codes
#include "sync.h"
#include "edcui_interface.h"
#include "edcparams.h"
#include "edcapp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <future>

#include <event2/event.h>
#include <event2/http.h>
#include <event2/thread.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>

#ifdef EVENT__HAVE_NETINET_IN_H
#include <netinet/in.h>
#ifdef _XOPEN_SOURCE_EXTENDED
#include <arpa/inet.h>
#endif
#endif


namespace
{

/** Maximum size of http request (request line + headers) */
const size_t MAX_HEADERS_SIZE = 8192;

/** HTTP request work item */
class HTTPWorkItem : public EDCHTTPClosure
{
public:
    HTTPWorkItem(
		std::unique_ptr<EDCHTTPRequest> _req, 
		            const std::string & _path, 
		  const EDCHTTPRequestHandler & _func):
      req(std::move(_req)), path(_path), func(_func)
    {
    }
    void operator()()
    {
        func(req.get(), path);
    }

    std::unique_ptr<EDCHTTPRequest> req;

private:
    std::string path;
    EDCHTTPRequestHandler func;
};

/** Simple work queue for distributing work over multiple threads.
 * Work items are simply callable objects.
 */
template <typename WorkItem>
class WorkQueue
{
private:
    /** Mutex protects entire object */
    std::mutex cs;
    std::condition_variable cond;
    std::deque<std::unique_ptr<WorkItem>> queue;
    bool running;
    size_t maxDepth;
    int numThreads;

    /** RAII object to keep track of number of running worker threads */
    class ThreadCounter
    {
    public:
        WorkQueue &wq;
        ThreadCounter(WorkQueue &w): wq(w)
        {
            std::lock_guard<std::mutex> lock(wq.cs);
            wq.numThreads += 1;
        }
        ~ThreadCounter()
        {
            std::lock_guard<std::mutex> lock(wq.cs);
            wq.numThreads -= 1;
            wq.cond.notify_all();
        }
    };

public:
    WorkQueue(size_t _maxDepth) :running(true),
                                 maxDepth(_maxDepth),
                                 numThreads(0)
    {
    }
    /** Precondition: worker threads have all stopped
     * (call WaitExit)
     */
    ~WorkQueue()
    {
    }
    /** Enqueue a work item */
    bool Enqueue(WorkItem* item)
    {
        std::unique_lock<std::mutex> lock(cs);
        if (queue.size() >= maxDepth) 
		{
            return false;
        }
        queue.emplace_back(std::unique_ptr<WorkItem>(item));
        cond.notify_one();
        return true;
    }
    /** Thread function */
    void Run()
    {
        ThreadCounter count(*this);
        while (running) 
		{
            std::unique_ptr<WorkItem> i;
            {
                std::unique_lock<std::mutex> lock(cs);
                while (running && queue.empty())
                    cond.wait(lock);
                if (!running)
                    break;
                i = std::move(queue.front());
                queue.pop_front();
            }
            (*i)();
        }
    }
    /** Interrupt and exit loops */
    void Interrupt()
    {
        std::unique_lock<std::mutex> lock(cs);
        running = false;
        cond.notify_all();
    }
    /** Wait for worker threads to exit */
    void WaitExit()
    {
        std::unique_lock<std::mutex> lock(cs);
        while (numThreads > 0)
            cond.wait(lock);
    }

    /** Return current depth of queue */
    size_t Depth()
    {
        std::unique_lock<std::mutex> lock(cs);
        return queue.size();
    }
};


struct HTTPPathHandler
{
    HTTPPathHandler() {}
    HTTPPathHandler(std::string _prefix, bool _exactMatch, EDCHTTPRequestHandler _handler):
        prefix(_prefix), exactMatch(_exactMatch), handler(_handler)
    {
    }
    std::string prefix;
    bool exactMatch;
    EDCHTTPRequestHandler handler;
};

/** HTTP module state */

//! HTTP server
struct evhttp* eventHTTP = 0;

//! List of subnets to allow RPC connections from
std::vector<CSubNet> rpc_allow_subnets;

//! Work queue for handling longer requests off the event loop thread
WorkQueue<EDCHTTPClosure>* workQueue = 0;

//! Handlers for (sub)paths
std::vector<HTTPPathHandler> pathHandlers;

//! Bound listening sockets
std::vector<evhttp_bound_socket *> boundSockets;

/** Check if a network address is allowed to access the Equibit HTTP server */
bool ClientAllowed(const CNetAddr& netaddr)
{
    if (!netaddr.IsValid())
        return false;

    for( const CSubNet & subnet : rpc_allow_subnets)
        if (subnet.Match(netaddr))
            return true;

    return false;
}

/** Initialize ACL list for Equibit HTTP server */
bool InitHTTPAllowList()
{
	EDCparams & params = EDCparams::singleton();

    rpc_allow_subnets.clear();
    CNetAddr localv4;
    CNetAddr localv6;
    LookupHost("127.0.0.1", localv4, false);
    LookupHost("::1", localv6, false);
    rpc_allow_subnets.push_back(CSubNet(localv4, 8)); // always allow IPv4 local subnet
    rpc_allow_subnets.push_back(CSubNet(localv6));    // always allow IPv6 localhost

    if (params.rpcallowip.size() > 0) 
	{
        const std::vector<std::string>& vAllow = params.rpcallowip;
        for( std::string strAllow : vAllow) 
		{
            CSubNet subnet;
            LookupSubNet(strAllow.c_str(), subnet);
            if (!subnet.IsValid()) 
			{
                edcUiInterface.ThreadSafeMessageBox(
                    strprintf("Invalid -eb_rpcallowip subnet specification: %s. Valid are a single IP (e.g. 1.2.3.4), a network/netmask (e.g. 1.2.3.4/255.255.255.0) or a network/CIDR (e.g. 1.2.3.4/24).", strAllow),
                    "", CEDCClientUIInterface::MSG_ERROR);
                return false;
            }
            rpc_allow_subnets.push_back(subnet);
        }
    }

    std::string strAllowed;
    for (const CSubNet& subnet : rpc_allow_subnets)
        strAllowed += subnet.ToString() + " ";
    edcLogPrint("http", "Allowing HTTP connections from: %s\n", strAllowed);

    return true;
}

/** HTTP request method as string - use for logging only */
std::string RequestMethodString(EDCHTTPRequest::RequestMethod m)
{
    switch (m) 
	{
    case EDCHTTPRequest::GET:
        return "GET";
        break;
    case EDCHTTPRequest::POST:
        return "POST";
        break;
    case EDCHTTPRequest::HEAD:
        return "HEAD";
        break;
    case EDCHTTPRequest::PUT:
        return "PUT";
        break;
    default:
        return "unknown";
    }
}

/** HTTP request callback */
void http_request_cb(struct evhttp_request * req, void * arg)
{
    std::unique_ptr<EDCHTTPRequest> hreq(new EDCHTTPRequest(req));

    edcLogPrint("http", "Received a %s request for %s from %s\n",
             RequestMethodString(hreq->GetRequestMethod()), hreq->GetURI(), hreq->GetPeer().ToString());

    // Early address-based allow check
    if (!ClientAllowed(hreq->GetPeer())) 	
	{
        hreq->WriteReply(HTTP_FORBIDDEN);
        return;
    }

    // Early reject unknown HTTP methods
    if (hreq->GetRequestMethod() == EDCHTTPRequest::UNKNOWN) 
	{
        hreq->WriteReply(HTTP_BADMETHOD);
        return;
    }

    // Find registered handler for prefix
    std::string strURI = hreq->GetURI();
    std::string path;
    std::vector<HTTPPathHandler>::const_iterator i = pathHandlers.begin();
    std::vector<HTTPPathHandler>::const_iterator iend = pathHandlers.end();

    for (; i != iend; ++i) 
	{
        bool match = false;
        if (i->exactMatch)
            match = (strURI == i->prefix);
        else
            match = (strURI.substr(0, i->prefix.size()) == i->prefix);

        if (match) 
		{
            path = strURI.substr(i->prefix.size());
            break;
        }
    }

    // Dispatch to worker thread
    if (i != iend) 
	{
        std::unique_ptr<HTTPWorkItem> item(new HTTPWorkItem(std::move(hreq), path, i->handler));
        assert(workQueue);
        if (workQueue->Enqueue(item.get()))
            item.release(); /* if true, queue took ownership */
        else 
		{
            edcLogPrintf("WARNING: request rejected because http work queue depth exceeded, it can be increased with the -eb_rpcworkqueue= setting\n");
            item->req->WriteReply(HTTP_INTERNAL, "Work queue depth exceeded");
        }
    } 
	else 
	{
        hreq->WriteReply(HTTP_NOTFOUND);
    }
}

/** Callback to reject HTTP requests after shutdown. */
void http_reject_request_cb(struct evhttp_request * req, void*)
{
    edcLogPrint("http", "Rejecting request while shutting down\n");
    evhttp_send_error(req, HTTP_SERVUNAVAIL, NULL);
}

/** Event dispatcher thread */
bool ThreadHTTP(struct event_base* base, struct evhttp* http)
{
    RenameThread("equibit-http");
    edcLogPrint("http", "Entering http event loop\n");
    event_base_dispatch(base);
    // Event loop will be interrupted by InterruptHTTPServer()
    edcLogPrint("http", "Exited http event loop\n");
	return event_base_got_break(base) == 0;
}

/** Bind Equibit HTTP server to specified addresses */
bool HTTPBindAddresses(struct evhttp* http)
{
	EDCparams & params = EDCparams::singleton();

    int defaultPort = params.rpcport;
    std::vector<std::pair<std::string, uint16_t> > endpoints;

    // Determine what addresses to bind to
    if (params.rpcallowip.size() == 0) 
	{ 
		// Default to loopback if not allowing external IPs
        endpoints.push_back(std::make_pair("::1", defaultPort));
        endpoints.push_back(std::make_pair("127.0.0.1", defaultPort));

        if (params.rpcbind.size() > 0 ) 
		{
            edcLogPrintf("WARNING: option -eb_rpcbind was ignored because -eb_rpcallowip was not specified, refusing to allow everyone to connect\n");
        }
    } 
	else if (params.rpcbind.size() > 0) 
	{ 
		// Specific bind address
        const std::vector<std::string>& vbind = params.rpcbind;

        for(std::vector<std::string>::const_iterator i = vbind.begin(); 
			i != vbind.end(); ++i) 
		{
            int port = defaultPort;
            std::string host;
            SplitHostPort(*i, port, host);
            endpoints.push_back(std::make_pair(host, port));
        }
    } 
	else 
	{ 
		// No specific bind address specified, bind to any
        endpoints.push_back(std::make_pair("::", defaultPort));
        endpoints.push_back(std::make_pair("0.0.0.0", defaultPort));
    }

    // Bind addresses
    for (std::vector<std::pair<std::string, uint16_t> >::iterator i = endpoints.begin(); i != endpoints.end(); ++i) 
	{
        edcLogPrint("http", "Binding RPC on address %s port %i\n", i->first, i->second);
        evhttp_bound_socket *bind_handle = evhttp_bind_socket_with_handle(http, i->first.empty() ? NULL : i->first.c_str(), i->second);

        if (bind_handle) 
		{
            boundSockets.push_back(bind_handle);
        } 
		else 
		{
            edcLogPrintf("Binding RPC on address %s port %i failed.\n", i->first, i->second);
        }
    }
    return !boundSockets.empty();
}

/** Simple wrapper to set thread name and run work queue */
void HTTPWorkQueueRun(WorkQueue<EDCHTTPClosure>* queue)
{
    RenameThread("equibit-httpworker");
    queue->Run();
}

/** libevent event log callback */
void libevent_log_cb(int severity, const char *msg)
{
#ifndef EVENT_LOG_WARN
// EVENT_LOG_WARN was added in 2.0.19; but before then _EVENT_LOG_WARN existed.
# define EVENT_LOG_WARN _EVENT_LOG_WARN
#endif
    if (severity >= EVENT_LOG_WARN) // Log warn messages and higher without debug category
        edcLogPrintf("libevent: %s\n", msg);
    else
        edcLogPrint("libevent", "libevent: %s\n", msg);
}
}

bool edcInitHTTPServer()
{
	EDCapp & theApp = EDCapp::singleton();
	EDCparams & params = EDCparams::singleton();

    struct evhttp * http = 0;
    struct event_base* base = 0;

    if (!InitHTTPAllowList())
        return false;

    // Redirect libevent's logging to our own log
    event_set_log_callback(&libevent_log_cb);

#if LIBEVENT_VERSION_NUMBER >= 0x02010100
    // If -eb_debug=libevent, set full libevent debugging.
    // Otherwise, disable all libevent debugging.
    if (edcLogAcceptCategory("libevent"))
        event_enable_debug_logging(EVENT_DBG_ALL);
    else
        event_enable_debug_logging(EVENT_DBG_NONE);
#endif
#ifdef WIN32
    evthread_use_windows_threads();
#else
    evthread_use_pthreads();
#endif

    base = event_base_new(); // XXX RAII
    if (!base) 
	{
        edcLogPrintf("Couldn't create an event_base: exiting\n");
        return false;
    }

    /* Create a new evhttp object to handle requests. */
    http = evhttp_new(base); // XXX RAII
    if (!http) 
	{
        edcLogPrintf("couldn't create evhttp. Exiting.\n");
        event_base_free(base);
        return false;
    }

    evhttp_set_timeout(http, params.rpcservertimeout);
    evhttp_set_max_headers_size(http, MAX_HEADERS_SIZE);
    evhttp_set_max_body_size(http, MAX_SIZE);
    evhttp_set_gencb(http, http_request_cb, NULL);

    if (!HTTPBindAddresses(http)) 
	{
        edcLogPrintf("Unable to bind any endpoint for RPC server\n");
        evhttp_free(http);
        event_base_free(base);
        return false;
    }

    edcLogPrint("http", "Initialized Equibit HTTP server\n");

    int workQueueDepth = std::max((long)params.rpcworkqueue, 1L);
    edcLogPrintf("HTTP: creating work queue of depth %d\n", workQueueDepth);

    workQueue = new WorkQueue<EDCHTTPClosure>(workQueueDepth);
    theApp.eventBase( base );
    eventHTTP = http;
    return true;
}

namespace
{
std::thread threadHTTP;
std::future<bool> threadResult;
}

bool edcStartHTTPServer()
{
	EDCapp & theApp = EDCapp::singleton();
	EDCparams & params = EDCparams::singleton();

    edcLogPrint("http", "Starting Equibit HTTP server\n");

    int rpcThreads = std::max((long)params.rpcthreads, 1L);

    edcLogPrintf("HTTP: starting %d worker threads\n", rpcThreads);

    std::packaged_task<bool(event_base*, evhttp*)> task(ThreadHTTP);
    threadResult = task.get_future();
    threadHTTP = std::thread(std::bind(std::move(task), theApp.eventBase(), eventHTTP));

    for (int i = 0; i < rpcThreads; i++) 
	{
        std::thread rpc_worker(HTTPWorkQueueRun, workQueue);
        rpc_worker.detach();
    }

    return true;
}

void edcInterruptHTTPServer()
{
    edcLogPrint("http", "Interrupting Equibit HTTP server\n");

    if (eventHTTP) 
	{
        // Unlisten sockets
        for (evhttp_bound_socket *socket :  boundSockets) 
		{
            evhttp_del_accept_socket(eventHTTP, socket);
        }
        // Reject requests on current connections
        evhttp_set_gencb(eventHTTP, http_reject_request_cb, NULL);
    }
    if (workQueue)
        workQueue->Interrupt();
}

void edcStopHTTPServer()
{
	EDCapp & theApp = EDCapp::singleton();

    edcLogPrint("http", "Stopping Equibit HTTP server\n");

    if (workQueue) 
	{
        edcLogPrint("http", "Waiting for HTTP worker threads to exit\n");
        workQueue->WaitExit();
        delete workQueue;
    }

    if (theApp.eventBase()) 
	{
        edcLogPrint("http", "Waiting for HTTP event thread to exit\n");
        // Give event loop a few seconds to exit (to send back last RPC responses), then break it
        // Before this was solved with event_base_loopexit, but that didn't work as expected in
        // at least libevent 2.0.21 and always introduced a delay. In libevent
        // master that appears to be solved, so in the future that solution
        // could be used again (if desirable).
        // (see discussion in https://github.com/bitcoin/bitcoin/pull/6990)

		if (threadResult.valid() && 
		threadResult.wait_for(std::chrono::milliseconds(2000)) == std::future_status::timeout)
		{
            edcLogPrintf("HTTP event loop did not exit within allotted time, sending loopbreak\n");
            event_base_loopbreak(theApp.eventBase());
        }
        threadHTTP.join();
    }
    if (eventHTTP) 
	{
        evhttp_free(eventHTTP);
        eventHTTP = 0;
    }
    if (theApp.eventBase()) 
	{
        event_base_free(theApp.eventBase());
        theApp.eventBase( NULL );
    }
    edcLogPrint("http", "Stopped Equibit HTTP server\n");
}

static void httpevent_callback_fn(evutil_socket_t, short, void* data)
{
    // Static handler: simply call inner handler
    EDCHTTPEvent *self = ((EDCHTTPEvent*)data);

    self->handler();

    if (self->deleteWhenTriggered)
        delete self;
}

EDCHTTPEvent::EDCHTTPEvent(
	                struct event_base * base, 
	                               bool _deleteWhenTriggered, 
	  const std::function<void(void)> & _handler):
  deleteWhenTriggered(_deleteWhenTriggered), 
  handler(_handler)
{
    ev = event_new(base, -1, 0, httpevent_callback_fn, this);
    assert(ev);
}

EDCHTTPEvent::~EDCHTTPEvent()
{
    event_free(ev);
}

void EDCHTTPEvent::trigger(struct timeval* tv)
{
    if (tv == NULL)
        event_active(ev, 0, 0); // immediately trigger event in main thread
    else
        evtimer_add(ev, tv); // trigger after timeval passed
}

EDCHTTPRequest::EDCHTTPRequest(struct evhttp_request* req) : req(req),
                                                       replySent(false)
{
}

EDCHTTPRequest::~EDCHTTPRequest()
{
    if (!replySent) 	
	{
        // Keep track of whether reply was sent to avoid request leaks
        edcLogPrintf("%s: Unhandled request\n", __func__);
        WriteReply(HTTP_INTERNAL, "Unhandled request");
    }
    // evhttpd cleans up the request, as long as a reply was sent.
}

std::pair<bool, std::string> EDCHTTPRequest::GetHeader(const std::string& hdr)
{
    const struct evkeyvalq* headers = evhttp_request_get_input_headers(req);

    assert(headers);
    const char* val = evhttp_find_header(headers, hdr.c_str());

    if (val)
        return std::make_pair(true, val);
    else
        return std::make_pair(false, "");
}

std::string EDCHTTPRequest::ReadBody()
{
    struct evbuffer* buf = evhttp_request_get_input_buffer(req);

    if (!buf)
        return "";
    size_t size = evbuffer_get_length(buf);

    /** Trivial implementation: if this is ever a performance bottleneck,
     * internal copying can be avoided in multi-segment buffers by using
     * evbuffer_peek and an awkward loop. Though in that case, it'd be even
     * better to not copy into an intermediate string but use a stream
     * abstraction to consume the evbuffer on the fly in the parsing algorithm.
     */
    const char* data = (const char*)evbuffer_pullup(buf, size);
    if (!data) // returns NULL in case of empty buffer
        return "";

    std::string rv(data, size);
    evbuffer_drain(buf, size);

    return rv;
}

void EDCHTTPRequest::WriteHeader(const std::string& hdr, const std::string& value)
{
    struct evkeyvalq* headers = evhttp_request_get_output_headers(req);
    assert(headers);
    evhttp_add_header(headers, hdr.c_str(), value.c_str());
}

/** Closure sent to main thread to request a reply to be sent to
 * a HTTP request.
 * Replies must be sent in the main loop in the main http thread,
 * this cannot be done from worker threads.
 */
void EDCHTTPRequest::WriteReply(int nStatus, const std::string& strReply)
{
    assert(!replySent && req);

	EDCapp & theApp = EDCapp::singleton();

    // Send event to main http thread to send reply message
    struct evbuffer* evb = evhttp_request_get_output_buffer(req);
    assert(evb);
    evbuffer_add(evb, strReply.data(), strReply.size());

    EDCHTTPEvent* ev = new EDCHTTPEvent(theApp.eventBase(), true,
        std::bind(evhttp_send_reply, req, nStatus, (const char*)NULL, (struct evbuffer *)NULL));

    ev->trigger(0);
    replySent = true;
    req = 0; // transferred back to main thread
}

CService EDCHTTPRequest::GetPeer()
{
    evhttp_connection* con = evhttp_request_get_connection(req);
    CService peer;

    if (con) 
	{
        // evhttp retains ownership over returned address string
        const char* address = "";
        uint16_t port = 0;
        evhttp_connection_get_peer(con, (char**)&address, &port);
		LookupNumeric(address, peer, port);
    }

    return peer;
}

std::string EDCHTTPRequest::GetURI()
{
    return evhttp_request_get_uri(req);
}

EDCHTTPRequest::RequestMethod EDCHTTPRequest::GetRequestMethod()
{
    switch (evhttp_request_get_command(req)) 
	{
    case EVHTTP_REQ_GET:
        return GET;
        break;
    case EVHTTP_REQ_POST:
        return POST;
        break;
    case EVHTTP_REQ_HEAD:
        return HEAD;
        break;
    case EVHTTP_REQ_PUT:
        return PUT;
        break;
    default:
        return UNKNOWN;
        break;
    }
}

void edcRegisterHTTPHandler(
	      const std::string & prefix, 
	                     bool exactMatch, 
const EDCHTTPRequestHandler & handler)
{
    edcLogPrint("http", "Registering Equibit HTTP handler for %s (exactmatch %d)\n", prefix, exactMatch);
    pathHandlers.push_back(HTTPPathHandler(prefix, exactMatch, handler));
}

void edcUnregisterHTTPHandler(const std::string &prefix, bool exactMatch)
{
    std::vector<HTTPPathHandler>::iterator i = pathHandlers.begin();
    std::vector<HTTPPathHandler>::iterator iend = pathHandlers.end();
    for (; i != iend; ++i)
        if (i->prefix == prefix && i->exactMatch == exactMatch)
            break;
    if (i != iend)
    {
        edcLogPrint("http", "Unregistering Equibit HTTP handler for %s (exactmatch %d)\n", prefix, exactMatch);
        pathHandlers.erase(i);
    }
}

