/*
 *    Copyright (c) 2021, The OpenThread Authors.
 *    All rights reserved.
 *
 *    Redistribution and use in source and binary forms, with or without
 *    modification, are permitted provided that the following conditions are met:
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *    3. Neither the name of the copyright holder nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *    POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef OTBR_COMMON_CALLBACK_HPP_
#define OTBR_COMMON_CALLBACK_HPP_

#include <functional>

namespace otbr {

template <class T> class OnceCallback;

template <template <typename...> class, typename...> struct is_instantiation : public std::false_type
{
};

template <template <typename...> class U, typename... T> struct is_instantiation<U, U<T...>> : public std::true_type
{
};

/**
 * A callback which can be invoked at most once.
 *
 * IsNull is guaranteed to return true once the callback has been invoked.
 *
 * Example usage:
 *  OnceCallback square([](int x) { return x * x; });
 *  std::move(square)(5); // Returns 25.
 *  std::move(square)(6); // Crashes since `square` has already run.
 *  square(7); // Compiling error.
 *
 * Inspired by Chromium base::OnceCallback
 * (https://chromium.googlesource.com/chromium/src.git/+/refs/heads/main/base/callback.h).
 *
 */
template <typename R, typename... Args> class OnceCallback<R(Args...)>
{
private:
    using FuncType = std::function<R(Args...)>;

public:
    template <typename T, typename P = typename std::enable_if<!is_instantiation<OnceCallback, T>::value>::type>
    OnceCallback(T &&func)
        : mFunc(std::forward<T>(func))
    {
    }

    OnceCallback(const OnceCallback &) = delete;
    OnceCallback &operator=(const OnceCallback &) = delete;
    OnceCallback(OnceCallback &&)                 = default;
    OnceCallback &operator=(OnceCallback &&) = default;

    R operator()(Args...) const &
    {
        static_assert(!sizeof(*this), "OnceCallback::() can only be invoked on a non-const "
                                      "rvalue, i.e. std::move(callback)().");
    }

    R operator()(Args... args) &&
    {
        // Move `this` to a local variable to clear internal state
        // before invoking the callback function.
        OnceCallback cb = std::move(*this);

        return cb.mFunc(std::forward<Args>(args)...);
    }

    bool IsNull() const { return mFunc == nullptr; }

private:
    FuncType mFunc;
};

} // namespace otbr

#endif // OTBR_COMMON_CALLBACK_HPP_
