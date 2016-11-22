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
	PollResult( );

	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
	{
		READWRITE(results_);
	}

	void addVote( );

private:
	//            Answer  Count
	std::map<std::string, unsigned>	results_;
};
