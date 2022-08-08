#pragma once

#include <boost/math/special_functions/binomial.hpp>
#include <boost/multiprecision/cpp_bin_float.hpp>
#include "utils.h"

namespace osuCrypto {

	u64 h1LengthInBytes = 32;
    u64 bucket1 = 1 << 10;
    u64 bucket2 = 1 << 10;

	u64 getWidthMeetStatSecParam(u64 n1, u64 n2, u64 m, u64 statSecParam, u64 cmpSecParam) {
		typedef boost::multiprecision::number<boost::multiprecision::backends::cpp_bin_float<16>> T;
		T p = boost::multiprecision::pow(1 - T(1.0) / m, n2);
		T _1p = T(1.0) - p;
		T negl = T(1.0) / (u64(1) << statSecParam);
		u64 width = 128;
		T sec = 1.0;
		for (;;) {
			T sum = 0.0;
			for (u64 k = 0; k < cmpSecParam; k++) {
				sum += boost::math::binomial_coefficient<T>(width, k) *
						boost::multiprecision::pow(p, k) *
						boost::multiprecision::pow(_1p, width - k);
			}
			sec = sum * n1;
			if (sec <= negl) {
				break;
			}
			width += 50;
		}
		while (sec <= negl) {
			width -= 1;
			T sum = 0.0;
			for (u64 k = 0; k < cmpSecParam; k++) {
				sum += boost::math::binomial_coefficient<T>(width, k) *
						boost::multiprecision::pow(p, k) *
						boost::multiprecision::pow(_1p, width - k);
			}
			sec = sum * n1;
		}
		return width + 1;
	}
}