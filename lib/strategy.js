/**
 * Creates an instance of `Strategy`.
 *
 * @constructor
 * @api public
 */
function Strategy() {
    this.name = 'passport-one-session-per-user'
}

/**
 * Authenticate request.
 *
 * This function must be overridden by subclasses.  In abstract form, it always
 * throws an exception.
 *
 * @param {Object} req The request to authenticate.
 * @param {Object} [options] Strategy-specific options.
 * @api public
 */
var loggedInUsers = [];
var passport = require('passport');

Strategy.prototype.authenticate = function(req, next) {
    var self = this;

    // If there is not logged in user, do nothing.
    if (!req.user) {
        return self.pass()
    }

    // If there is logged in user, let's see if he exists in [loggedInUsers] array
    passport.serializeUser(req.user, function (err, thisUserId) {
        var found = false;
        for (var i = 0; i < loggedInUsers.length; i++) {
            //console.log("thisUserId:" + thisUserId + " req.sessionID:" + req.sessionID);
            //console.log("loggedIn.user:" + loggedInUsers[i].user + " loggedIn.sessionId:" + loggedInUsers[i].sessionID);
            //console.log("loggedIn.logout:" + loggedInUsers[i].logout);
            if (JSON.stringify(thisUserId) === JSON.stringify(loggedInUsers[i].user)) { //if a user is logged in more than once
                //console.log("same user logged in");
                if (JSON.stringify(loggedInUsers[i].sessionID) !== JSON.stringify(req.sessionID)) { //if the same user has multiple sessions
                    //Same user logged in from other session
                    // Flag him to `logout`  next time he request and pge
                    //console.log("same user logged in from other session");
                    //loggedInUsers[i].sessions++;
                    //console.log("session count:" + loggedInUsers[i].sessions );
                    //if(loggedInUsers[i].sessions === 3)

                    loggedInUsers[i].logout = true;


                } else if (loggedInUsers[i].logout) {
                    // This user flagged to logout. Log him out, and remove this instance from array;
                    found = true;
                    loggedInUsers.splice(i, 1);
                    req.logout();
                    //  console.log("this user has been flagged to log out. logging out");
                    return self.pass()
                } else {
                    // this user and this sessionID already in Array.
                    // We don't need to do add him again.
                    //console.log("this user and sessionID already in array");
                    found = true
                }
            }
        }

        // If the current session && curred User not in Array. Add it to array
        if (!found) {
            loggedInUsers.push({
                //sessions:1,
                user: thisUserId,
                sessionID: req.sessionID
            })
        }
        self.pass()
    })
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
