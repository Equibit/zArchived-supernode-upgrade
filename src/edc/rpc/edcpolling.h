// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "serialize.h"


class Poll
{
public:
	Poll() {}
	Poll( const CKeyID & issuerID,
	 const std::string & question, 
	 const std::vector<std::string> & answers,
	 const std::string & start,
	 const std::string & end);

	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
	{
		READWRITE(question_);
		READWRITE(answers_);
		READWRITE(start_);
		READWRITE(end_);
	}

	bool validAnswer( const std::string & ans ) const;
	bool validDate( time_t d ) const;

	uint160	id() const;

	std::string toJSON() const;

private:
	CKeyID 		issuerID_;
	std::string question_;
	std::vector<std::string> answers_;
	time_t 		start_;
	time_t 		end_;
};


class PollResult
{
public:
	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
	{
		READWRITE(results_);
	}

	enum Type
	{
		GENERAL,// General proxy voted
		ISSUER,	// Issuer specific proxy voted
		POLL,	// Poll specific proxy voted
		OWNER,	// Owner of equibit voted
		INVALID	// Vote was made by proxy that has not be registered for owner
	};

	void addVote( const std::string & ans, const CKeyID & id, Type t );

private:

	std::map<std::string, std::map<CKeyID, int>>	results_;
};
