/*
This file is part of FlashMQ example plugin 'plugin_libcurl'
and is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <http://unlicense.org/>
*/

#include "vendor/flashmq_plugin.h"

#include <curl/curl.h>
#include <sys/epoll.h>
#include <stdexcept>
#include <map>


#include "pluginstate.h"
#include "curl_functions.h"
#include "authenticatingclient.h"
#include <jwt-cpp/jwt.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <string>
// include jwt-cpp
#include "jwt-cpp/jwt.h"


int flashmq_plugin_version()
{
    return FLASHMQ_PLUGIN_VERSION;
}

void flashmq_plugin_main_init(std::unordered_map<std::string, std::string> &plugin_opts)
{
    (void)plugin_opts;

    if (curl_global_init(CURL_GLOBAL_ALL) != 0)
        throw std::runtime_error("Global curl init failed to init");
}

void flashmq_plugin_main_deinit(std::unordered_map<std::string, std::string> &plugin_opts)
{
    (void)plugin_opts;

    curl_global_cleanup();
}
// new text test
void flashmq_plugin_allocate_thread_memory(void **thread_data, std::unordered_map<std::string, std::string> &plugin_opts)
{
    (void)plugin_opts;

    PluginState *state = new PluginState();
    *thread_data = state;
}

void flashmq_plugin_deallocate_thread_memory(void *thread_data, std::unordered_map<std::string, std::string> &plugin_opts)
{
    (void)plugin_opts;

    PluginState *state = static_cast<PluginState*>(thread_data);
    delete state;
}

/**
 * @brief flashmq_plugin_init We have nothing to do here, really.
 * @param thread_data
 * @param plugin_opts
 * @param reloading
 */
void flashmq_plugin_init(void *thread_data, std::unordered_map<std::string, std::string> &plugin_opts, bool reloading)
{
    (void)thread_data;
    (void)plugin_opts;
    (void)reloading;
}

void flashmq_plugin_deinit(void *thread_data, std::unordered_map<std::string, std::string> &plugin_opts, bool reloading)
{
    (void)thread_data;
    (void)plugin_opts;
    (void)reloading;
}

/**
 * @brief flashmq_plugin_poll_event_received
 * @param thread_data
 * @param fd
 * @param events
 * @param p A pointer to a data structure we assigned when watching the fd. We only use libcurl so we know we have to give it to
 *        libcurl. Had we also used something else, we would have needed this to figure out what the fd is.
 */
void flashmq_plugin_poll_event_received(void *thread_data, int fd, uint32_t events, const std::weak_ptr<void> &p)
{
    (void)p;

    PluginState *s = static_cast<PluginState*>(thread_data);

    int new_events = CURL_CSELECT_ERR;

    if (events & EPOLLIN)
    {
        new_events &= ~CURL_CSELECT_ERR;
        new_events |= CURL_CSELECT_IN;
    }
    if (events & EPOLLOUT)
    {
        new_events &= ~CURL_CSELECT_ERR;
        new_events |= CURL_CSELECT_OUT;
    }

    int n = -1;
    curl_multi_socket_action(s->curlMulti, fd, new_events, &n);

    check_all_active_curls(s->curlMulti);
}



enum class Allowed_Access {
	playbook,
	bettingClient,
	sportsClient,
	pump,
};

bool allow_user_access(const std::string &username)
{
	const std::map<Allowed_Access, std::string> allowmap = {
		{Allowed_Access::playbook, "playbook"},
		{Allowed_Access::sportsClient, "sports-client"},
		{Allowed_Access::bettingClient, "anonymous-betting-client"},
		{Allowed_Access::pump, "pump"},
	};

	for (const auto &kv : allowmap) {
		if (kv.second == username) {
			return true;
		}
	}
	return false;
}

std::string get_env_var( std::string const & key )
{
    char * val = getenv( key.c_str() );
    return val == NULL ? std::string("") : std::string(val);
}


std::string base64_decode(const std::string &in) {
    BIO *bio, *b64;
    int decodeLen = (int)in.length() * 3 / 4;
    std::string out(decodeLen, '\0');

    bio = BIO_new_mem_buf(in.data(), (int)in.length());
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    // Do not use newlines to flush buffer
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    int len = BIO_read(bio, &out[0], (int)in.length());
    if (len > 0) out.resize(len);
    else out.clear();

    BIO_free_all(bio);
    return out;
}

AuthResult flashmq_plugin_login_check(void *thread_data, const std::string &clientid, const std::string &username, const std::string &password,
                                      const std::vector<std::pair<std::string, std::string>> *userProperties, const std::weak_ptr<Client> &client)
{
    (void)clientid;
    (void)userProperties;
    (void)client;


    flashmq_logf(LOG_INFO, "username: %s", username.c_str());

    if (allow_user_access(username)){
        return AuthResult::success;
    }
    
    // base64 decode the environment variable AUTH_PUBLICKEY
    const std::string rsa_pub_env_key = get_env_var("AUTH_PUBLICKEY");
    const std::string rsa_pub_key = base64_decode(rsa_pub_env_key);

    const std::string token = password;
    if (token.empty())
    {
        flashmq_logf(LOG_ERR, "No token found for username: %s", username.c_str());
        return AuthResult::error;
    }
    
    
    // decode the username and password, if they are jwt tokens, and check if they are valid.
    try{
        /* [allow rsa algorithm] */
        auto verify = jwt::verify()
                        // We only need an RSA public key to verify tokens
                        .allow_algorithm(jwt::algorithm::rs256(rsa_pub_key, "", "", ""));
        /* [decode jwt token] */
        auto decoded = jwt::decode(token);
        flashmq_logf(LOG_INFO, "Decoded JWT token successfully");
        verify.verify(decoded);
        flashmq_logf(LOG_INFO, "Verified JWT token successfully with public key");
        
        return AuthResult::success;
    } catch (const std::exception &e) {
        flashmq_logf(LOG_ERR, "Failed to decode JWT token: %s", e.what());
        std::cout << "Caught exception: " << e.what() << std::endl;
        // print the exception message
        return AuthResult::error;
    }

    return AuthResult::login_denied;

}

AuthResult flashmq_plugin_acl_check(void *thread_data, const AclAccess access, const std::string &clientid, const std::string &username,
                                               const std::string &topic, const std::vector<std::string> &subtopics, const std::string &shareName,
                                               std::string_view payload, const uint8_t qos, const bool retain,
                                               const std::optional<std::string> &correlationData, const std::optional<std::string> &responseTopic,
                                               const std::vector<std::pair<std::string, std::string>> *userProperties)
{
    (void)thread_data;
    (void)access;
    (void)clientid;
    (void)subtopics;
    (void)qos;
    (void)(retain);
    (void)userProperties;
    (void)topic;
    (void)payload;
    (void)shareName;
    (void)correlationData;
    (void)responseTopic;

    return AuthResult::success;
}

