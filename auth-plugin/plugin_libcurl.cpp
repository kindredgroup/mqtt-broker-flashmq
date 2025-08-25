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
#include <chrono>

#include "pluginstate.h"
#include "curl_functions.h"
#include "authenticatingclient.h"
#include <jwt-cpp/jwt.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <string>
#include "parallel_hashmap/phmap.h"
#include <shared_mutex>

/* 
 * creates a p hashmap with shared mutex so read/write is thread safe. Read is lock free.
 * this is a global variable, so it is shared between all threads because acl check can happen in any thread.
 * 2**N so 2**4 = 16 sub maps, so lock is applied to sub map so concurrency is intrinsinc to the map.
 */
const int N = 4;
using TokenCache = phmap::parallel_flat_hash_map<
    std::string,
    std::int64_t,
    phmap::priv::hash_default_hash<std::string>,
    phmap::priv::hash_default_eq<std::string>,
    phmap::priv::Allocator<phmap::priv::Pair<const std::string, std::int64_t>>,
    N,
    std::shared_mutex>;

static TokenCache token_expiry_cache;

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
    token_expiry_cache.clear();

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



bool allow_user_access(const std::string &username) {
    const std::vector<std::string> allowed_users = {
        "playbook",
        "sports-client",
        "anonymous-betting-client",
        "pump"
    };

    return std::find(allowed_users.begin(), allowed_users.end(), username) != allowed_users.end();
}

std::string get_env_var(std::string const &key) {
    char *val = getenv(key.c_str());
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
    if (len > 0)
        out.resize(len);
    else
        out.clear();

    BIO_free_all(bio);
    return out;
}


void flashmq_plugin_client_disconnected(void *thread_data, const std::string &clientid){
    (void)thread_data;
    // erase is thread safe as it acquires write lock on the shard.
    token_expiry_cache.erase(clientid);   
}


AuthResult flashmq_plugin_login_check(void *thread_data, const std::string &clientid, const std::string &username, const std::string &password,
                                      const std::vector<std::pair<std::string, std::string>> *userProperties, const std::weak_ptr<Client> &client)
{
    (void)clientid;
    (void)userProperties;
    (void)client;
    (void)thread_data;

    flashmq_logf(LOG_INFO, "username: %s", username.c_str());

    if (allow_user_access(username))
    {
        return AuthResult::success;
    }

    // base64 decode the environment variable AUTH_PUBLICKEY
    const std::string rsa_pub_env_key = get_env_var("AUTH_PUBLICKEY");
    const std::string rsa_pub_key = base64_decode(rsa_pub_env_key);

    const std::string token = password;

    if (token.empty()) {
        flashmq_logf(LOG_ERR, "No token found for username: %s", username.c_str());
        return AuthResult::error;
    }

    // decode the username and password, if they are jwt tokens, and check if they are valid.
    try {
        /* [allow rsa algorithm] */
        auto jwt_verify = jwt::verify()
                          .allow_algorithm(jwt::algorithm::rs256(rsa_pub_key, "", "", ""));
        /* [decode jwt token] */
        auto decoded = jwt::decode(token);
        jwt_verify.verify(decoded);
        std::int64_t exp_epoch = decoded.get_payload_claim("exp").to_json().get<int64_t>();
        /* 
         * upserts the cache with the clientid and the exp_epoch.
         * thread safe write with try_emplace_l as it acquires write lock on the shard (sub maps). Lock is specific to the sub map
         */
        token_expiry_cache.try_emplace_l(
            clientid,
            [&](auto& kv) { kv.second = exp_epoch; }, 
            exp_epoch  // construct if missing
        );

        flashmq_logf(LOG_INFO, "Verified JWT token successfully for user: %s", username.c_str());
        return AuthResult::success;
    } catch (const std::exception &e) {
        flashmq_logf(LOG_ERR, "Failed to decode JWT token: %s", e.what());
        std::cout << "Caught exception: " << e.what() << std::endl;
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
    (void)subtopics;
    (void)qos;
    (void)(retain);
    (void)userProperties;
    (void)payload;
    (void)shareName;
    (void)correlationData;
    (void)responseTopic;

    // SYS topics are published every 10 seconds, this allow broker internal $SYS topics to be published
    bool is_broker_internal_topic = (username.empty() && clientid.empty()) && topic.rfind("$SYS", 0) == 0 && access == AclAccess::write;
    bool is_allowed_user = allow_user_access(username);

    if (is_broker_internal_topic || is_allowed_user) {
        return AuthResult::success;
    }
 
    std::int64_t exp_epoch = 0;
    // thread safe read with if_contains
    bool cache_hit = token_expiry_cache.if_contains(clientid, [&](const TokenCache::value_type &kv) {
        exp_epoch = kv.second;
    });



    if (cache_hit) {
        flashmq_logf(LOG_DEBUG, "JWT verification cache hit for user: %s and exp: %lld", username.c_str(), exp_epoch);
        // jwt expiry is in epoch seconds
        std::int64_t now_epoch = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        bool token_expired = now_epoch > exp_epoch;

        if(token_expired) {
            flashmq_logf(LOG_DEBUG, "JWT verification cache expired for user: %s", username.c_str());
            token_expiry_cache.erase(clientid);
            return AuthResult::acl_denied;
        }

        return AuthResult::success;
    }

    return AuthResult::acl_denied;
}
