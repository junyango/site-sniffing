function getNormalizedTime(value) {
    return value == 0 ? '0 seconds' :
           value < 100 ? (Math.round(value * 10)/10).toString() + ' seconds' :
           value < 60 * 60 ? 'over ' + parseInt(value/60) + ' minutes' :
           value < 60 * 60 * 24 ? 'over ' + parseInt(value/(60 * 60)) + ' hours' :
           'over ' + parseInt(value/(60 * 60 * 24)) + ' days';
}

function getNormalizedNumber(value) {
    return value == null ? '0' :
           value < 1000 ? value.toString() :
           value < 1000000 ? 'over ' + Math.floor(value/1000) + 'K' :
           'over ' + Math.floor(value/1000000) + 'M';
}

function updateAllPropsRecursive(obj, func) {
    for (var prop in obj) {
        if (obj.hasOwnProperty(prop)) {
            obj[prop] = func(obj[prop]);
            if (obj[prop] !== null && typeof(obj[prop]) == "object") {
                updateAllPropsRecursive(obj[prop], func);
            }
        }
    }
}

function convertStringDatesToDates(obj) {
    updateAllPropsRecursive(obj, function(value) {
        return typeof value == "string" && isNaN(Date.parse(value)) == false ? new Date(Date.parse(value)) : value;
    });
}

function mergeObjects(source, target) {
    for (var attr in source) {
        if (source.hasOwnProperty(attr) == false)
            continue;

        if (typeof source[attr] == "object") {
            target[attr] = {};
            mergeObjects(source[attr], target[attr]);
        } else {
            target[attr] = source[attr];
        }
    }

    return target;
}

var localStorageService = new function() {
    this.readJson = function(key) {
        try {
            var value = localStorage[key];
            return value ? JSON.parse(value) : null;
        } catch(e) { }
    };

    this.writeJson = function(key, value) {
        try {
            localStorage[key] = JSON.stringify(value);
            return true;
        } catch(e) { }
    };

    this.remove = function(key) {
        try {
            delete localStorage[key];
            return true;
        } catch(e) {
            return false;
        }
    };
};

var jobRunner = new function() {
    var jobs = {}; // name > intervalId,startTime
    var that = this;

    this.run = function(name, func, intervalSeconds, runNow, expirationSeconds) {
        if (jobs[name])
            throw new Error('a job with the name ' + name + ' already exists');

        if (runNow) {
            var stop = runSafely(func);
            if (stop)
                return;
        }

        var intervalId = callEvery(function() {
            if (expirationSeconds) {
                var now = new Date();
                var startTime = jobs[name].startTime;
                var seconds = (now - startTime) / 1000;
                if (seconds >= expirationSeconds) {
                    that.stop(name);
                    return;
                }
            }

            var stop = runSafely(func);
            if (stop)
                that.stop(name);

        }, intervalSeconds * 1000);

        jobs[name] = {
            intervalId: intervalId,
            startTime: new Date()
        };
    };

    this.stop = function(name) {
        if (jobs[name]) {
            var intervalId = jobs[name].intervalId;
            delete jobs[name];
            stopInterval(intervalId);
        }
    };

    this.isRunning = function(name) {
        return jobs.hasOwnProperty(name);
    };

    function runSafely(func) {
        try {
            return func();
        } catch (e) { }
    }
};

var updatingDataFromServer = function(settings) {
    var dataName = settings.dataName;
    var dataNameStorageKey = dataName + 'List';
    var dataDateStorageKey = dataName + 'Date';
    var timeGetter = settings.timeGetter || utcTimeGetter;
    var expirationMinutes = settings.expirationMinutes;
    var resourceUrl = settings.resourceUrl;
    var onUpdate = settings.onUpdate;
    var isRawResponse = settings.isRawResponse;
    var lastUpdateTime = null;

    this.start = function() {
        getStorageValue(dataNameStorageKey, function(dataExists, data) {
            if (dataExists) {
                runSafely(function() {
                    onUpdate(data, true);
                });

                getStorageValue(dataDateStorageKey, function(dateExists, date) {
                    if (dateExists)
                        lastUpdateTime = new Date(date);
                });
            } else {
                loadData();
            }
        });

        jobRunner.run(settings.dataName + '-load-data', loadDataInterval, 60, false);
    };

    this.forceUpdate = function() {
        loadData();
    };

    function loadDataInterval() {
        var shouldLoadData = lastUpdateTime == null;
        if (shouldLoadData === false) {
            var lastUpdateMinsDiff = (timeGetter() - lastUpdateTime) / (1000 * 60);
            shouldLoadData = lastUpdateMinsDiff >= expirationMinutes;
        }

        shouldLoadData && loadData();
    }

    function loadData() {
        callUrl({ method: 'GET', url: resourceUrl, raw: isRawResponse, headers: [{ name: 'Cache-Control', value: 'max-age=0' }] }, function(data) {
            runSafely(function() {
                onUpdate(data, false);
            });

            var now = timeGetter();
            lastUpdateTime = now;
            setSingleStorageValue(dataNameStorageKey, data, function(success) {
                if (success) {
                    setSingleStorageValue(dataDateStorageKey, now.toString());
                }
            });
        });
    }
};


// for some reason Chrome sometimes doesn't load all files of the extension and it doesn't work, as reported by users
// this will check that the extension works and if not it will restart it
if (!window.heartbeatInterval) {
    window.heartbeatInterval = setTimeout(function() {
        if ($st && $stats && blockingRules && setupUser && !window.forceReload)
            return;

        function sendReloadEvent(data) {
            try {
                function toUTCString(time) {
                    return time.getUTCFullYear() + '-' + (time.getUTCMonth() + 1) + '-' + time.getUTCDate() + ' ' + time.getUTCHours() + ':' + time.getUTCMinutes() + ':' + time.getUTCSeconds();
                }

                var obj = {
                    eventTime: toUTCString(new Date()),
                    browserId: 1,
                    browserVersion: 'NA',
                    appId: 1,
                    appVersion: '0',
                    os: 'NA',
                    eventTypeId: 17,
                    logBatchGuid: 'NA',
                    geo: 'NA',
                    data: data
                };

                (new Image()).src = 'https://log.standsapp.org/log3.gif?data=[' + encodeURIComponent(JSON.stringify(obj)) + ']';
            } catch (e) {}
        }

        chrome.storage.local.get('userData', function(items) {
            if (chrome.runtime.lastError) {
                sendReloadEvent({errUser: chrome.runtime.lastError});
            } else {
                sendReloadEvent({publicUserId: items.userData.publicUserId});
            }

            setTimeout(chrome.runtime.reload, 2000);
        });
    }, 60 * 1000);
}