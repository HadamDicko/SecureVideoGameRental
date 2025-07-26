/***************************
    Hadam Dicko
    2025
    server.cpp
***************************/

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>

#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <cerrno>
#include <system_error>
#include <fstream>
#include <algorithm>
#include <array>
#include <optional>
#include <filesystem>
#include <format>
#include <thread>
#include <chrono>
#include <vector>
#include <sstream>
#include <map>
#include <iomanip> // For std::setw, std::setfill
#include "p1_helper.h"

#define BACKLOG 10
#define MAXDATASIZE 1024

// client session state
enum class Mode
{
    NONE, // initial state
    BROWSE,
    RENT,
    MYGAMES
};

// maintain client session info
struct ClientSession
{
    Mode currentMode = Mode::NONE;
    std::string clientIP;
    std::vector<int> rentedGames;   // games rented by client
    std::map<int, int> gameRatings; // games rated by client (game_id -> rating)
    bool authenticated = false;
    std::string pendingUsername;
};

// user credentials
struct UserCredentials
{
    std::string username;
    std::vector<unsigned char> salt;
    std::vector<unsigned char> hash;
    int iterations;
};

// base64 encoding/decoding functions
std::string base64_encode(const unsigned char *data, size_t length);
std::vector<unsigned char> base64_decode(const std::string &input);

// password generation and validation
std::string generate_password();
bool validate_password(const std::string &password);

// salt generation
std::vector<unsigned char> generate_salt();

// password hashing and verification
std::vector<unsigned char> hash_password(const std::string &password, const std::vector<unsigned char> &salt, int iterations);
bool verify_password(const std::string &password, const std::vector<unsigned char> &salt, const std::vector<unsigned char> &stored_hash, int iterations);

// global map to store credentials
std::map<std::string, UserCredentials> userCredentials;

// global variables
std::vector<Game> games;                             // game db
std::map<std::string, ClientSession> clientSessions; // active session(s)

// global variable for OpenSSL
SSL_CTX *ctx = nullptr;

// signal handler for SIGCHLD
void sigchld_handler(int s)
{
    (void)s;
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;
    errno = saved_errno;
}

// get sockaddr (IPv4/IPv6)
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

std::string toUpper(const std::string &str)
{
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c)
                   { return std::toupper(c); });
    return result;
}

// parse command (string) into tokens
std::vector<std::string> parseCommand(const std::string &cmd)
{
    std::vector<std::string> tokens;
    std::stringstream ss(cmd);
    std::string token;
    while (ss >> token)
    {
        // convert the first token (the command) to uppercase
        if (tokens.empty())
        {
            tokens.push_back(toUpper(token));
        }
        else
        {
            // keep other tokens as is (for usernames, passwords, etc.)
            tokens.push_back(token);
        }
    }
    return tokens;
}

// initialize OpenSSL
void init_openssl()
{
    // SSL_load_error_strings();
    // OpenSSL_add_ssl_algorithms();
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
}

// cleanup OpenSSL
void cleanup_openssl()
{
    if (ctx)
    {
        SSL_CTX_free(ctx);
    }
    // EVP_cleanup();
}

// configure TLS context
SSL_CTX *create_ssl_context()
{
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    if (!ctx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // set TLS version to 1.3 only
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1)
    {
        perror("Failed to set minimum TLS version");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1)
    {
        perror("Failed to set maximum TLS version");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // set secure cipher suites for TLS 1.3
    if (SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256") != 1)
    {
        perror("Failed to set cipher suites");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    //READ attempted fix
    SSL_CTX_set_options(ctx, SSL_OP_ALL);                // Enable all workarounds
    SSL_CTX_clear_options(ctx, SSL_OP_NO_RENEGOTIATION); // Don't explicitly forbid renegotiation

    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_timeout(ctx, 3600); // 1 hour timeout

    return ctx;
}

// configure certificates
void configure_certificates(SSL_CTX *ctx)
{
    // set certificate file
    if (SSL_CTX_use_certificate_file(ctx, "p3server.crt", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // set private key file
    if (SSL_CTX_use_PrivateKey_file(ctx, "p3server.key", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // verify the private key
    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the certificate\n");
        exit(EXIT_FAILURE);
    }
}

// initialize the credential system
void init_credential_system()
{
    // clear any existing credentials
    userCredentials.clear();

    // create new empty file for user info 
    std::ofstream new_file(".games_shadow", std::ios::trunc);
    new_file.close();

}

bool user_exists(const std::string &username);
std::optional<UserCredentials> get_user_credentials(const std::string &username);

// add a new user to the credential system
void add_user(const std::string &username, const std::string &password)
{
    // check if user already exists
    if (user_exists(username))
    {
        std::cout << "User " << username << " already exists, updating credentials." << std::endl;
        // delete the old record from the file before adding the new one
        std::ifstream inFile(".games_shadow");
        std::vector<std::string> lines;
        std::string line;

        // read all lines except the one with this username
        while (std::getline(inFile, line))
        {
            if (line.substr(0, username.length()) != username ||
                (line.length() > username.length() && line[username.length()] != ':'))
            {
                lines.push_back(line);
            }
        }
        inFile.close();

        // write back all lines except the one we removed
        std::ofstream outFile(".games_shadow");
        for (const auto &l : lines)
        {
            outFile << l << std::endl;
        }
        outFile.close();
    }

    // create new credentials
    UserCredentials credentials;
    credentials.username = username;
    credentials.iterations = 10000; // fixed for this assignment

    // senerate a salt
    credentials.salt = generate_salt();

    // hash the password
    credentials.hash = hash_password(password, credentials.salt, credentials.iterations);

    // store in our map (overwrite if existing)
    userCredentials[username] = credentials;

    // append to the .games_shadow file
    std::ofstream shadow_file(".games_shadow", std::ios::app);
    if (!shadow_file)
    {
        std::cerr << "Error opening .games_shadow for writing" << std::endl;
        return;
    }

    // format: username:$pbkdf2-sha256$work_factor$salt_base64$hash_base64
    shadow_file << username << ":$pbkdf2-sha256$"
                << credentials.iterations << "$"
                << base64_encode(credentials.salt.data(), credentials.salt.size()) << "$"
                << base64_encode(credentials.hash.data(), credentials.hash.size())
                << std::endl;

    shadow_file.close();
}

// check if a user exists
bool user_exists(const std::string &username)
{
    return userCredentials.find(username) != userCredentials.end();
}

// get user credentials
std::optional<UserCredentials> get_user_credentials(const std::string &username)
{
    auto it = userCredentials.find(username);
    if (it != userCredentials.end())
    {
        return it->second;
    }
    return std::nullopt;
}

// handle BROWSE commands (LIST SEARCH SHOW)
std::string handleBrowseMode(const std::vector<std::string> &tokens, ClientSession &session)
{
    if (tokens.empty())
        return "400 BAD REQUEST";

    //  LIST
    if (tokens[0] == "LIST")
    {
        std::string result = "250 Games:\n";
        bool found = false;

        // get the filter type (if any) - FIXED: Properly extract filter argument
        std::string filter = tokens.size() > 1 ? tokens[1] : "";

        std::string filter_lower = filter;
        std::transform(filter_lower.begin(), filter_lower.end(), filter_lower.begin(), [](unsigned char c)
                       { return std::tolower(c); });

        // add: Validate filter type if provided
        if (!filter.empty() &&
            filter != "title" &&
            filter != "genre" &&
            filter != "platform" &&
            filter != "rating")
        {
            return "400 BAD REQUEST"; // ADDED: Return error for invalid filter type
        }

        // fix: split logic based on whether filter is provided
        // no filter, list all games with full info (original behavior)
        if (filter.empty())
        {
            for (const auto &game : games)
            {
                result += std::format("{}. {} ({}) - {}\n", game.id, game.title, game.platform, game.genre);
                found = true;
            }
        }
        else
        {
            // change the header based on the filter
            result = std::format("250 {}s:\n", filter);

            // track unique values to avoid duplicates
            std::vector<std::string> uniqueValues;

            // collect all unique values for the specified filter
            for (const auto &game : games)
            {
                std::string value;
                // extract the appropriate field based on filter
                if (filter == "title")
                    value = game.title;
                else if (filter == "genre")
                    value = game.genre;
                else if (filter == "platform")
                    value = game.platform;
                else if (filter == "rating")
                    value = game.esrb;

                // only add unique values
                if (std::find(uniqueValues.begin(), uniqueValues.end(), value) == uniqueValues.end())
                {
                    uniqueValues.push_back(value);
                }
            }

            // sort the values alphabetically
            std::sort(uniqueValues.begin(), uniqueValues.end());

            // add each unique value to the result
            for (const auto &value : uniqueValues)
            {
                result += value + "\n";
                found = true;
            }
        }

        return found ? result : "304 NO CONTENT";
    }
    //  SEARCH
    else if (tokens[0] == "SEARCH" && tokens.size() >= 3)
    {
        std::string filter = tokens[1];
        std::string keyword = tokens[2];
        std::string result = "250 Search results:\n";
        bool found = false;

        for (const auto &game : games)
        {
            bool matches = false;
            if (filter == "title")
                matches = game.title.find(keyword) != std::string::npos;
            else if (filter == "platform")
                matches = game.platform == keyword;
            else if (filter == "genre")
                matches = game.genre == keyword;
            else if (filter == "rating")
                matches = game.esrb == keyword;

            if (matches)
            {
                result += std::format("{}. {} ({}) - {}\n", game.id, game.title, game.platform, game.genre);
                found = true;
            }
        }
        return found ? result : "304 NO CONTENT";
    }
    // SHOW
    else if (tokens[0] == "SHOW" && tokens.size() >= 2)
    {
        int gameId = std::stoi(tokens[1]);
        bool availabilityOnly = tokens.size() > 2 && tokens[2] == "availability";

        auto it = std::find_if(games.begin(), games.end(), [gameId](const Game &g)
        { 
        return g.id == gameId; 
        });

        if (it != games.end())
        {
            if (availabilityOnly)
            {
                return std::format("250 Availability: {}, Copies: {}", it->available ? "True" : "False", it->copies);
            }
            return std::format("250 Game Details:\nTitle: {}\nPlatform: {}\nGenre: {}\n" "Year: {}\nESRB: {}\nAvailable: {}\nCopies: {}", it->title, it->platform, it->genre, it->year, it->esrb, it->available ? "Yes" : "No", it->copies);
        }
        return "404 NOT FOUND";
    }
    return "400 BAD REQUEST";
}

// handle RENT commands
std::string handleRentMode(const std::vector<std::string> &tokens, ClientSession &session)
{
    if (tokens.empty())
        return "400 BAD REQUEST";

    //  CHECKOUT
    if (tokens[0] == "CHECKOUT" && tokens.size() == 2)
    {
        int gameId = std::stoi(tokens[1]);
        auto it = std::find_if(games.begin(), games.end(), [gameId](const Game &g)
        { 
            return g.id == gameId; 
        });

        if (it != games.end())
        {
            if (!it->available || it->copies == 0)
            {
                return "403 FORBIDDEN";
            }
            it->copies--;
            if (it->copies == 0)
                it->available = false;
            session.rentedGames.push_back(gameId);
            return "250 Game checked out successfully";
        }
        return "404 NOT FOUND";
    }
    //  RETURN
    else if (tokens[0] == "RETURN" && tokens.size() == 2)
    {
        int gameId = std::stoi(tokens[1]);
        auto it = std::find(session.rentedGames.begin(), session.rentedGames.end(), gameId);

        if (it != session.rentedGames.end())
        {
            auto gameIt = std::find_if(games.begin(), games.end(), [gameId](const Game &g)
                                       { return g.id == gameId; });
            gameIt->copies++;
            gameIt->available = true;
            session.rentedGames.erase(it);
            return "250 Game returned successfully";
        }
        return "404 Game not checked out";
    }
    return "400 BAD REQUEST";
}

// handle MYGAMES commands
std::string handleMyGamesMode(const std::vector<std::string> &tokens, ClientSession &session)
{
    if (tokens.empty())
        return "400 BAD REQUEST";
    //  HISTORY
    if (tokens[0] == "HISTORY")
    {
        if (session.rentedGames.empty())
        {
            return "304 NO CONTENT";
        }
        std::string result = "250 Rental History:\n";
        for (int gameId : session.rentedGames)
        {
            auto it = std::find_if(games.begin(), games.end(), [gameId](const Game &g)
            { 
                return g.id == gameId; 
            });
            result += std::format("{}. {}\n", gameId, it->title);
        }
        return result;
    }
    //  RECOMMEND
    else if (tokens[0] == "RECOMMEND")
    {
        std::string filter = tokens.size() > 1 ? tokens[1] : "";
        std::string result = "250 Recommendations:\n";
        bool found = false;

        // simple recommendation based on genre/platform of rented games
        for (const auto &game : games)
        {
            if (!game.available)
                continue;

            for (int rentedId : session.rentedGames)
            {
                auto rentedGame = std::find_if(games.begin(), games.end(),[rentedId](const Game &g)
                { 
                    return g.id == rentedId; 
                });

                bool matches = false;
                if (filter.empty() || filter == "genre")
                    matches = game.genre == rentedGame->genre;
                else if (filter == "platform")
                    matches = game.platform == rentedGame->platform;

                if (matches && game.id != rentedId)
                {
                    result += std::format("{}. {} ({}) - {}\n", game.id, game.title, game.platform, game.genre);
                    found = true;
                    break;
                }
            }
        }
        return found ? result : "304 NO CONTENT";
    }
    //  RATE
    else if (tokens[0] == "RATE" && tokens.size() == 3)
    {
        int gameId = std::stoi(tokens[1]);
        int rating = std::stoi(tokens[2]);

        if (rating < 1 || rating > 10)
        {
            return "400 Invalid rating";
        }

        auto it = std::find(session.rentedGames.begin(), session.rentedGames.end(), gameId);
        if (it != session.rentedGames.end())
        {
            session.gameRatings[gameId] = rating;
            return "250 Rating successful";
        }
        return "404 Game not found in rental history";
    }
    return "400 BAD REQUEST";
}

// handle client commands
std::string handleCommand(const std::string &command, ClientSession &session)
{
    auto tokens = parseCommand(command);
    if (tokens.empty())
        return "400 BAD REQUEST";

    // Allow only USER or PASS if not authenticated yet
    if (!session.authenticated)
    {
        // USER command
        if (tokens[0] == "USER")
        {
            if (tokens.size() < 2)
                return "400 BAD REQUEST";

            std::string username = tokens[1];
            session.pendingUsername = username;

            if (user_exists(username))
            {
                return "300 Password required";
            }
            else
            {
                // new user registration protocol
                std::string password;
                // Try generating valid passwords until one passes validation
                do
                {
                    password = generate_password();
                } while (!validate_password(password));

                // add the new user to our system
                add_user(username, password);

                // return the generated password to the client
                return "200 New user registered, password: " + password;
            }
        }
        // PASS command
        else if (tokens[0] == "PASS")
        {
            if (tokens.size() < 2 || session.pendingUsername.empty())
            {
                return "400 BAD REQUEST";
            }

            // extract just the password - remove any trailing "closed" string
            std::string password = tokens[1];
            if (password.length() > 8 && password.substr(password.length() - 6) == "closed")
            {
                password = password.substr(0, password.length() - 6);
            }

            auto credentials_opt = get_user_credentials(session.pendingUsername);

            std::cout << "Received password: " << password << std::endl;
            std::cout << "Username: " << session.pendingUsername << std::endl;

            if (!credentials_opt)
            {
                return "410 Authentication failed";
            }

            auto credentials = credentials_opt.value();

            std::cout << "Stored salt size: " << credentials.salt.size() << std::endl;
            std::cout << "Stored hash size: " << credentials.hash.size() << std::endl;

            // add these detailed hash comparison debug lines
            std::vector<unsigned char> computed_hash = hash_password(password, credentials.salt, credentials.iterations);
            std::cout << "Computed hash size: " << computed_hash.size() << std::endl;

            // print the first few bytes of both hashes in hexadecimal for comparison
            std::cout << "First 8 bytes of stored hash: ";
            for (int i = 0; i < std::min(8, static_cast<int>(credentials.hash.size())); i++)
            {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(credentials.hash[i]) << " ";
            }
            std::cout << std::dec << std::endl;

            std::cout << "First 8 bytes of computed hash: ";
            for (int i = 0; i < std::min(8, static_cast<int>(computed_hash.size())); i++)
            {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(computed_hash[i]) << " ";
            }
            std::cout << std::dec << std::endl;

            // also print the salt in hex for debugging
            std::cout << "Salt in hex: ";
            for (int i = 0; i < std::min(8, static_cast<int>(credentials.salt.size())); i++)
            {
                std::cout << std::hex << std::setw(2) << std::setfill('0')
                          << static_cast<int>(credentials.salt[i]) << " ";
            }
            std::cout << std::dec << std::endl;

            // debugging the hash comparison
            bool match = true;
            for (size_t i = 0; i < computed_hash.size(); i++)
            {
                if (computed_hash[i] != credentials.hash[i])
                {
                    match = false;
                    std::cout << "Hash mismatch at position " << i << std::endl;
                    break;
                }
            }
            std::cout << "Hash match: " << (match ? "Yes" : "No") << std::endl;

            // normal verify
            if (verify_password(password, credentials.salt, credentials.hash, credentials.iterations))
            {
                session.authenticated = true;
                return "210 Authentication successful";
            }
            else
            {
                return "410 Authentication failed";
            }
        }
        // no other commands allowed before authentication
        else
        {
            return "401 Authentication required";
        }
    }

    // regular handling for authenticated users
    if (tokens[0] == "HELP")
    {
        std::string help = "200 Available commands:\n";
        switch (session.currentMode)
        {
        case Mode::NONE:
            help += "HELP, BROWSE, RENT, MYGAMES, BYE";
            break;
        case Mode::BROWSE:
            help += "LIST [filter], SEARCH <filter> <keyword>, SHOW <game_id> [availability]";
            break;
        case Mode::RENT:
            help += "CHECKOUT <game_id>, RETURN <game_id>";
            break;
        case Mode::MYGAMES:
            help += "HISTORY, RECOMMEND [filter], RATE <game_id> <rating>";
            break;
        }
        return help;
    }
    else if (tokens[0] == "BROWSE")
    {
        session.currentMode = Mode::BROWSE;
        return "210 Switched to Browse Mode";
    }
    else if (tokens[0] == "RENT")
    {
        session.currentMode = Mode::RENT;
        return "220 Switched to Rent Mode";
    }
    else if (tokens[0] == "MYGAMES")
    {
        session.currentMode = Mode::MYGAMES;
        return "230 Switched to Mygames Mode";
    }
    else if (tokens[0] == "BYE")
    {
        return "200 BYE";
    }

    std::cout << "Current mode: " << static_cast<int>(session.currentMode) << std::endl;
    std::cout << "Processing command: " << tokens[0] << std::endl;

    // Mode-specific commands
    switch (session.currentMode)
    {
    case Mode::BROWSE:
        return handleBrowseMode(tokens, session);
    case Mode::RENT:
        return handleRentMode(tokens, session);
    case Mode::MYGAMES:
        return handleMyGamesMode(tokens, session);
    default:
        return "503 Bad sequence of commands. Must enter a mode first.";
    }
}

//  individual client connections
void handleClient(int clientSocket, const std::string &clientIP)
{
    // set up SSL connection
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, clientSocket);

    // perform SSL handshake
    if (SSL_accept(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(clientSocket);
        return;
    }

    ClientSession session;
    session.clientIP = clientIP;

    std::array<char, MAXDATASIZE> buffer;
    bool running = true;
    int auth_failures = 0;

    while (running)
    {
        // receive data using SSL instead of plain recv
        int bytesReceived = SSL_read(ssl, buffer.data(), MAXDATASIZE - 1);
        if (bytesReceived <= 0)
        {
            int ssl_error = SSL_get_error(ssl, bytesReceived);
            if (ssl_error == SSL_ERROR_ZERO_RETURN)
            {
                // normal closure
                break;
            }
            else
            {
                // error
                ERR_print_errors_fp(stderr);
                break;
            }
        }

        buffer[bytesReceived] = '\0';
        std::string command(buffer.data());
        std::string response = handleCommand(command, session) + "\n";
        std::cout << response << std::endl;
        
        // check for authentication failure
        if (response.find("410 Authentication failed") == 0)
        {
            auth_failures++;
            if (auth_failures >= 2)
            {
                // send failure response before closing
                SSL_write(ssl, response.c_str(), response.length());
                running = false;
                break;
            }
        }

        // send data using SSL instead of plain send
        if (SSL_write(ssl, response.c_str(), response.length()) <= 0)
        {
            ERR_print_errors_fp(stderr);
            break;
        }

        if (command == "RENT" || command == "BROWSE" || command == "MYGAMES")
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            // for mode-switching commands, add extra error handling
            int write_result = SSL_write(ssl, response.c_str(), response.length());
            if (write_result <= 0)
            {
                int ssl_error = SSL_get_error(ssl, write_result);
                std::cerr << "SSL error during mode change: " << ssl_error << std::endl;

                // try to reset the SSL state without closing connection
                if (ssl_error == SSL_ERROR_SSL || ssl_error == SSL_ERROR_SYSCALL)
                {
                    // try to recover - this might not always work
                    SSL_clear(ssl);
                    continue; // try to keep the connection alive
                }
            }
        }

        auto tokens = parseCommand(command);
        if (!tokens.empty() && tokens[0] == "BYE") {
            // After sending the response, exit the loop
            break; // close connection
        }

        if (command == "BYE" || response.find("200 New user registered") == 0)
        {
            running = false;
            //break;
        }
    }

    // clean up SSL
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(clientSocket);
}

// Base64 encoding function
std::string base64_encode(const unsigned char *data, size_t length)
{
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, data, length);
    BIO_flush(b64);

    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);

    std::string result(bptr->data, bptr->length - 1); // -1 to remove newline
    BIO_free_all(b64);

    return result;
}

// Base64 decoding function
std::vector<unsigned char> base64_decode(const std::string &input)
{
    if (input.empty())
    {
        std::cerr << "Warning: Attempting to decode empty base64 string" << std::endl;
        return {};
    }

    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // newlines

    BIO *bmem = BIO_new_mem_buf(input.c_str(), input.length());
    bmem = BIO_push(b64, bmem);

    std::vector<unsigned char> result(input.length());
    int decoded_size = BIO_read(bmem, result.data(), input.length());

    if (decoded_size <= 0)
    {
        std::cerr << "Error decoding base64 string: " << input << std::endl;
        ERR_print_errors_fp(stderr);
        BIO_free_all(bmem);
        return {};
    }

    result.resize(decoded_size);
    BIO_free_all(bmem);
    return result;
}

// generate a random salt (16 bytes)
std::vector<unsigned char> generate_salt()
{
    std::vector<unsigned char> salt(16);
    RAND_bytes(salt.data(), salt.size());
    return salt;
}

// generate a random password (8 characters)
std::string generate_password()
{
    const std::string uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const std::string lowercase = "abcdefghijklmnopqrstuvwxyz";
    const std::string numbers = "0123456789";
    const std::string symbols = "!@#$%&*_-+=";
    const std::string all_chars = uppercase + lowercase + numbers + symbols;

    // ensure the password has at least one of each required type
    std::string password;

    // seed with a random value
    unsigned char rand_seed[4];
    RAND_bytes(rand_seed, sizeof(rand_seed));

    // first character must not be a symbol
    unsigned char index;
    RAND_bytes(&index, 1);
    password += (uppercase + lowercase + numbers)[index % (uppercase.length() + lowercase.length() + numbers.length())];

    // add at least one uppercase, one lowercase, one number, and one symbol
    unsigned char idx;
    RAND_bytes(&idx, 1);
    password += uppercase[idx % uppercase.length()];

    RAND_bytes(&idx, 1);
    password += lowercase[idx % lowercase.length()];

    RAND_bytes(&idx, 1);
    password += numbers[idx % numbers.length()];

    RAND_bytes(&idx, 1);
    password += symbols[idx % symbols.length()];

    // fill the rest of the password (total 8 chars)
    while (password.length() < 8)
    {
        RAND_bytes(&idx, 1);
        password += all_chars[idx % all_chars.length()];
    }

    // shuffle the password (except the first character)
    for (size_t i = 1; i < password.length(); i++)
    {
        RAND_bytes(&idx, 1);
        size_t j = 1 + (idx % (password.length() - 1)); // first character as is
        std::swap(password[i], password[j]);
    }

    return password;
}

// validate password strength
bool validate_password(const std::string &password)
{
    if (password.length() != 8)
        return false;

    const std::string symbols = "!@#$%&*_-+=";
    if (symbols.find(password[0]) != std::string::npos)
        return false;

    bool has_upper = false, has_lower = false, has_digit = false, has_symbol = false;

    for (char c : password)
    {
        if (isupper(c))
            has_upper = true;
        else if (islower(c))
            has_lower = true;
        else if (isdigit(c))
            has_digit = true;
        else if (symbols.find(c) != std::string::npos)
            has_symbol = true;
    }

    return has_upper && has_lower && has_digit && has_symbol;
}

// hash password using PBKDF2-HMAC-SHA256
std::vector<unsigned char> hash_password(const std::string &password, const std::vector<unsigned char> &salt, int iterations = 10000)
{
    std::vector<unsigned char> hash(32); // 32 bytes = 256 bits

    PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt.data(), salt.size(), iterations, EVP_sha256(), hash.size(), hash.data());

    return hash;
}

// verify if a password matches the stored hash
bool verify_password(const std::string &password, const std::vector<unsigned char> &salt, const std::vector<unsigned char> &stored_hash, int iterations = 10000)
{
    // safety check to avoid segmentation fault
    if (salt.empty() || stored_hash.empty())
    {
        std::cerr << "Error: Cannot verify password with empty salt or hash" << std::endl;
        return false;
    }

    std::vector<unsigned char> computed_hash = hash_password(password, salt, iterations);

    if (computed_hash.empty() || computed_hash.size() != stored_hash.size())
    {
        return false;
    }

    // constant-time comparison to prevent timing attacks
    unsigned char result = 0;
    for (size_t i = 0; i < computed_hash.size(); i++)
    {
        result |= computed_hash[i] ^ stored_hash[i];
    }

    return result == 0;
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: " << argv[0] << " <config_file>\n";
        return 1;
    }

    init_openssl();
    ctx = create_ssl_context();
    configure_certificates(ctx);

    // load games db
    games = loadGamesFromFile("games.db");

    // read configuration
    std::string configFileName = argv[1];
    std::optional<std::string> port;

    std::ifstream configFile(configFileName);
    std::string line;
    while (std::getline(configFile, line))
    {
        if (line.substr(0, 5) == "PORT=")
        {
            port = line.substr(5);
            break;
        }
    }
    configFile.close();

    if (!port)
    {
        std::cerr << "Port not found in configuration file\n";
        return 1;
    }

    // set up server
    struct addrinfo hints = {}, *servinfo, *p;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    int rv;
    if ((rv = getaddrinfo(nullptr, port->c_str(), &hints, &servinfo)) != 0)
    {
        std::cerr << "getaddrinfo: " << gai_strerror(rv) << '\n';
        return 1;
    }

    int sockfd;
    int yes = 1;

    init_credential_system();

    // bind to first available address
    for (p = servinfo; p != nullptr; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
            std::perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
        {
            std::perror("setsockopt");
            close(sockfd);
            continue;
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            std::perror("server: bind");
            close(sockfd);
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo);

    if (p == nullptr)
    {
        std::cerr << "server: failed to bind\n";
        return 2;
    }

    if (listen(sockfd, BACKLOG) == -1)
    {
        std::perror("listen");
        return 1;
    }

    // signal handler
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, nullptr) == -1)
    {
        std::perror("sigaction");
        return 1;
    }

    std::cout << "server: waiting for connections...\n";

    // main accept loop
    while (true)
    {
        struct sockaddr_storage clientAddr;
        socklen_t sinSize = sizeof(clientAddr);

        int newFd = accept(sockfd, (struct sockaddr *)&clientAddr, &sinSize);
        if (newFd == -1)
        {
            std::perror("accept");
            continue;
        }

        char clientIP[INET6_ADDRSTRLEN];
        inet_ntop(clientAddr.ss_family,
                  get_in_addr((struct sockaddr *)&clientAddr),
                  clientIP, sizeof clientIP);
        std::cout << "server: got connection from " << clientIP << std::endl;

        // create a new thread to handle the client
        std::thread(handleClient, newFd, std::string(clientIP)).detach();
    }
    cleanup_openssl();
    return 0;
}
