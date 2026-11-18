
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
#include <regex>
#include <fstream>
#include <sstream>

using namespace std;

struct URLInfo {
    string protocol;
    string host;
    string path;
    string query;
    string port;
    bool hasCredentials = false;
};

class PhishGuard {

private:

    int riskScore = 0;
    vector<string> warnings;

    string toLower(string text) {
        transform(text.begin(), text.end(),
                  text.begin(),
                  [](unsigned char c) {
                      return tolower(c);
                  });
        return text;
    }

    string trim(string text) {
        size_t first = text.find_first_not_of(" \t\r\n");

        if (first == string::npos)
            return "";

        size_t last = text.find_last_not_of(" \t\r\n");

        return text.substr(first, last - first + 1);
    }

    void addRisk(int points, string reason) {
        riskScore += points;
        warnings.push_back(reason);
    }

    bool isIPv4(string host) {

        regex pattern(
            R"(^([0-9]{1,3}\.){3}[0-9]{1,3}$)"
        );

        if (!regex_match(host, pattern))
            return false;

        stringstream ss(host);
        string part;

        while (getline(ss, part, '.')) {
            int number = stoi(part);

            if (number < 0 || number > 255)
                return false;
        }

        return true;
    }

    bool parseURL(string url, URLInfo &info) {

        url = trim(url);

        size_t protocolPosition = url.find("://");

        if (protocolPosition == string::npos) {
            cout << "Error: Missing URL protocol.\n";
            return false;
        }

        info.protocol = toLower(
            url.substr(0, protocolPosition)
        );

        if (info.protocol != "http" &&
            info.protocol != "https") {

            cout << "Error: Only HTTP and HTTPS URLs "
                 << "are supported.\n";

            return false;
        }

        size_t start = protocolPosition + 3;

        size_t end = url.find_first_of("/?#", start);

        string authority = url.substr(
            start,
            end == string::npos
                ? string::npos
                : end - start
        );

        if (authority.empty()) {
            cout << "Error: Missing hostname.\n";
            return false;
        }

        // Detect user information in authority
        size_t atPosition = authority.rfind('@');

        if (atPosition != string::npos) {

            info.hasCredentials = true;

            authority = authority.substr(atPosition + 1);
        }

        // Extract hostname and port
        if (authority.empty()) {
            cout << "Error: Invalid hostname.\n";
            return false;
        }

        if (authority[0] == '[') {

            size_t close = authority.find(']');

            if (close == string::npos) {
                cout << "Error: Invalid IPv6 address.\n";
                return false;
            }

            info.host = authority.substr(1, close - 1);

            if (close + 1 < authority.length()) {

                if (authority[close + 1] != ':') {
                    cout << "Error: Invalid port.\n";
                    return false;
                }

                info.port = authority.substr(close + 2);
            }
        }
        else {

            size_t colon = authority.rfind(':');

            if (colon != string::npos) {

                if (authority.find(':') != colon) {
                    cout << "Error: IPv6 addresses must "
                         << "use brackets.\n";
                    return false;
                }

                info.host = authority.substr(0, colon);
                info.port = authority.substr(colon + 1);
            }
            else {
                info.host = authority;
            }
        }

        info.host = toLower(info.host);

        if (info.host.empty()) {
            cout << "Error: Empty hostname.\n";
            return false;
        }

        if (!all_of(info.host.begin(), info.host.end(),
            [](unsigned char c) {
                return isalnum(c) || c == '.' ||
                       c == '-' || c == ':';
            })) {

            cout << "Error: Invalid hostname characters.\n";
            return false;
        }

        if (!info.port.empty()) {

            if (!all_of(info.port.begin(), info.port.end(),
                [](unsigned char c) {
                    return isdigit(c);
                })) {

                cout << "Error: Invalid port number.\n";
                return false;
            }

            try {
                int portNumber = stoi(info.port);

                if (portNumber < 1 || portNumber > 65535) {
                    cout << "Error: Port out of range.\n";
                    return false;
                }
            }
            catch (...) {
                cout << "Error: Invalid port number.\n";
                return false;
            }
        }

        // Extract path
        if (end != string::npos) {

            size_t pathEnd = url.find_first_of("?#", end);

            info.path = url.substr(
                end,
                pathEnd == string::npos
                    ? string::npos
                    : pathEnd - end
            );
        }

        // Extract query
        size_t queryPosition = url.find('?');

        if (queryPosition != string::npos) {

            size_t fragmentPosition =
                url.find('#', queryPosition);

            info.query = url.substr(
                queryPosition + 1,
                fragmentPosition == string::npos
                    ? string::npos
                    : fragmentPosition - queryPosition - 1
            );
        }

        return true;
    }

    void detectThreats(string url, URLInfo info) {

        riskScore = 0;
        warnings.clear();

        // Check 1: HTTP protocol
        if (info.protocol == "http") {
            addRisk(10, "Website does not use HTTPS.");
        }

        // Check 2: IP address instead of domain
        if (isIPv4(info.host)) {
            addRisk(30, "URL uses an IPv4 address as hostname.");
        }

        // Check 3: User information symbol
        if (info.hasCredentials) {
            addRisk(25, "URL contains user-information syntax (@).");
        }

        // Check 4: URL length
        if (url.length() > 120) {
            addRisk(15, "URL is unusually long.");
        }
        else if (url.length() > 75) {
            addRisk(10, "URL is longer than usual.");
        }

        // Check 5: Suspicious keywords
        vector<string> keywords = {
            "login",
            "verify",
            "password",
            "account",
            "secure",
            "banking",
            "update",
            "confirm",
            "signin"
        };

        string lowerURL = toLower(url);

        for (string word : keywords) {

            if (lowerURL.find(word) != string::npos) {

                addRisk(15,
                    "Suspicious keyword detected: " + word);

                break;
            }
        }

        // Check 6: Multiple hyphens in hostname
        int hyphenCount = count(
            info.host.begin(),
            info.host.end(),
            '-'
        );

        if (hyphenCount >= 2) {
            addRisk(10, "Hostname contains multiple hyphens.");
        }

        // Check 7: Too many subdomains
        int dotCount = count(
            info.host.begin(),
            info.host.end(),
            '.'
        );

        if (dotCount >= 3) {
            addRisk(10, "Hostname contains many subdomains.");
        }

        // Check 8: Internationalized domain encoding
        if (info.host.find("xn--") != string::npos) {
            addRisk(20, "Hostname contains punycode encoding.");
        }

        if (riskScore > 100)
            riskScore = 100;
    }

    string getRiskLevel() {

        if (riskScore < 20)
            return "LOW RISK";

        else if (riskScore < 50)
            return "MEDIUM RISK";

        else
            return "HIGH RISK";
    }

public:

    void analyze(string url) {

        URLInfo info;

        cout << "\n================================\n";
        cout << "       PHISHGUARD ANALYSIS\n";
        cout << "================================\n";

        if (!parseURL(url, info))
            return;

        cout << "\nURL COMPONENTS\n";
        cout << "Protocol : " << info.protocol << endl;
        cout << "Hostname : " << info.host << endl;
        cout << "Port     : "
             << (info.port.empty() ? "Default" : info.port)
             << endl;
        cout << "Path     : " << info.path << endl;
        cout << "Query    : " << info.query << endl;

        detectThreats(url, info);

        cout << "\nSECURITY ANALYSIS\n";

        if (warnings.empty()) {
            cout << "No configured warning indicators detected.\n";
        }
        else {
            for (string warning : warnings) {
                cout << "[WARNING] " << warning << endl;
            }
        }

        cout << "\nFINAL RESULT\n";
        cout << "Risk Score : " << riskScore << "/100\n";
        cout << "Risk Level : " << getRiskLevel() << endl;

        cout << "================================\n";
    }
};

int main() {

    PhishGuard scanner;

    string url;

    cout << "====================================\n";
    cout << "       PHISHGUARD v1.0\n";
    cout << "   PHISHING URL DETECTION SYSTEM\n";
    cout << "====================================\n";

    cout << "\nThis tool analyzes URL characteristics.\n";
    cout << "It does not guarantee website safety.\n";

    while (true) {

        cout << "\nEnter URL (or type exit): ";

        getline(cin, url);

        if (toLower(url) == "exit")
            break;

        if (url.empty()) {
            cout << "Please enter a URL.\n";
            continue;
        }

        scanner.analyze(url);
    }

    cout << "\nPhishGuard closed successfully.\n";

    return 0;
}
