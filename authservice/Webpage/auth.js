var g_apiDataMap = {};
var g_userAccount = null;
var g_authToken = null;
var g_subscriptionId = null;
var g_username = null;
var g_MouseDownTime;
var g_email = null;

$(document).ajaxError(function (event, jqxhr, settings, thrownError) {
    if (jqxhr.status != '401') {
        return;
    }
    console.log('Logging out ...');
    logout('Your session timedout, login again');
});

function logoutRedirect() {
    window.location.href = "/";
}

function mainLogout() {
    var request = $.ajax({
        url: getServer() + "/api/Account/LogOut",
        type: "POST",
        beforeSend: function (xhr) {
            xhr.setRequestHeader("Authorization", "Bearer " + g_authToken);
        },
        contentType: "application/json"
    });

    request.done(function (data) {
        console.log("Main Logout success");
        logoutRedirect();
    });

    request.fail(function (jqxhr, textStatus) {
        console.log("Main Logout fail");
    });
}

function getServer() {
    //return 'https://portal.duplocloud.net';
    return location.protocol + '//' + location.host;
}

function getSubscriptionId() {
    return g_subscriptionId;
}

function getOAuthToken() {
    var fragment = common.getFragment();
    console.log(fragment.accessToken);
    if ((fragment.accessToken != null) && (fragment.accessToken != "")) {
        localStorage.setItem("g_authToken", fragment.accessToken);
    }
    if ((fragment.g_subscriptionId != null) && (fragment.g_subscriptionId != "")) {
        localStorage.setItem("g_subscriptionId", fragment.g_subscriptionId);
    }
    g_authToken = localStorage.getItem("g_authToken");

    if ((fragment.external_user_name != null) && (fragment.external_user_name != "")) {
        localStorage.setItem("g_username", fragment.external_user_name);
    }
    g_username = localStorage.getItem("g_username");

    if ((fragment.external_email != null) && (fragment.external_email != "")) {
        localStorage.setItem("g_email", fragment.external_email);
    }
    g_email = localStorage.getItem("g_email");
    $("#email").text(g_email);
    $("#user").text(g_username);
}

window.common = (function () {
    var common = {};

    common.getFragment = function getFragment() {
        if (window.location.hash.indexOf("#") === 0) {
            return parseQueryString(window.location.hash.substr(1));
        } else {
            return {};
        }
    };

    function parseQueryString(queryString) {
        var data = {},
            pairs, pair, separatorIndex, escapedKey, escapedValue, key, value;

        if (queryString === null) {
            return data;
        }

        pairs = queryString.split("&");

        for (var i = 0; i < pairs.length; i++) {
            pair = pairs[i];
            separatorIndex = pair.indexOf("=");

            if (separatorIndex === -1) {
                escapedKey = pair;
                escapedValue = null;
            } else {
                escapedKey = pair.substr(0, separatorIndex);
                escapedValue = pair.substr(separatorIndex + 1);
            }

            key = decodeURIComponent(escapedKey);
            value = decodeURIComponent(escapedValue);

            data[key] = value;
        }
        window.history.replaceState(null, null, "/dashboard");
        return data;
    }
    return common;
})();

function resetAuth() {
    localStorage.removeItem("g_authToken");
    localStorage.removeItem("g_username");
    localStorage.removeItem("g_email");
}

function onLoadPage() {
    getOAuthToken();
}