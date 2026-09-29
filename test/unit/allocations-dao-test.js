const assert = require("assert");
const should = require("should");

describe("AllocationsDAO - NoSQL Injection Mitigation Tests", function() {
    "use strict";

    let AllocationsDAO;
    let allocationsDAO;
    let mockDb;
    let mockAllocationsCol;
    let mockUserDAO;

    before(function() {
        // Load the AllocationsDAO module
        AllocationsDAO = require("../../app/data/allocations-dao").AllocationsDAO;
    });

    beforeEach(function() {
        // Create mock collection with find method
        mockAllocationsCol = {
            find: function(criteria) {
                this.lastCriteria = criteria;
                return {
                    toArray: function(callback) {
                        // Return empty array for simplicity in these tests
                        callback(null, []);
                    }
                };
            },
            update: function(query, doc, options, callback) {
                callback(null);
            },
            lastCriteria: null
        };

        // Create mock database
        mockDb = {
            collection: function(name) {
                if (name === "allocations") {
                    return mockAllocationsCol;
                }
                // Mock users collection for UserDAO
                return {
                    findOne: function(query, callback) {
                        callback(null, {
                            _id: 1,
                            userId: 1,
                            userName: "testuser",
                            firstName: "Test",
                            lastName: "User"
                        });
                    }
                };
            }
        };

        // Create instance of AllocationsDAO with mock db
        allocationsDAO = new AllocationsDAO(mockDb);
    });

    describe("getByUserIdAndThreshold - Input Validation", function() {

        it("should sanitize JavaScript injection payload: 1'; return 1 == '1 by parsing to integer", function(done) {
            const userId = "2";
            const maliciousThreshold = "1'; return 1 == '1";

            // parseInt will extract "1" from this payload, making it safe
            // The key security property is that the raw string is never interpolated
            const originalFind = mockAllocationsCol.find;
            mockAllocationsCol.find = function(criteria) {
                return {
                    toArray: function(callback) {
                        should.exist(criteria.$where);
                        // Verify the injection payload was sanitized to just the integer
                        criteria.$where.should.equal("this.userId == 2 && this.stocks > 1");
                        // Verify the malicious code is NOT in the query
                        criteria.$where.should.not.match(/return 1 == '1/);
                        callback(null, []);
                    }
                };
            };

            allocationsDAO.getByUserIdAndThreshold(userId, maliciousThreshold, function(err, allocations) {
                mockAllocationsCol.find = originalFind;
                // Will get "no allocations" error from mock, but that's OK
                done();
            });
        });

        it("should sanitize infinite loop DoS payload: 5';while(true){};' by parsing to integer", function(done) {
            const userId = "2";
            const dosThreshold = "5';while(true){};'";

            // parseInt will extract "5" from this payload, making it safe
            const originalFind = mockAllocationsCol.find;
            mockAllocationsCol.find = function(criteria) {
                return {
                    toArray: function(callback) {
                        should.exist(criteria.$where);
                        // Verify the DoS payload was sanitized to just the integer
                        criteria.$where.should.equal("this.userId == 2 && this.stocks > 5");
                        // Verify the malicious code is NOT in the query
                        criteria.$where.should.not.match(/while\(true\)/);
                        callback(null, []);
                    }
                };
            };

            allocationsDAO.getByUserIdAndThreshold(userId, dosThreshold, function(err, allocations) {
                mockAllocationsCol.find = originalFind;
                done();
            });
        });

        it("should sanitize threshold with single quote injection attempt by parsing to integer", function(done) {
            const userId = "2";
            const maliciousThreshold = "10' || '1'=='1";

            // parseInt will extract "10" from this payload
            const originalFind = mockAllocationsCol.find;
            mockAllocationsCol.find = function(criteria) {
                return {
                    toArray: function(callback) {
                        should.exist(criteria.$where);
                        criteria.$where.should.equal("this.userId == 2 && this.stocks > 10");
                        // Verify the injection is NOT in the query
                        criteria.$where.should.not.match(/\|\|/);
                        callback(null, []);
                    }
                };
            };

            allocationsDAO.getByUserIdAndThreshold(userId, maliciousThreshold, function(err, allocations) {
                mockAllocationsCol.find = originalFind;
                done();
            });
        });

        it("should sanitize threshold with semicolon injection attempt by parsing to integer", function(done) {
            const userId = "2";
            const maliciousThreshold = "5; return true;";

            // parseInt will extract "5" from this payload
            const originalFind = mockAllocationsCol.find;
            mockAllocationsCol.find = function(criteria) {
                return {
                    toArray: function(callback) {
                        should.exist(criteria.$where);
                        criteria.$where.should.equal("this.userId == 2 && this.stocks > 5");
                        // Verify the injection is NOT in the query
                        criteria.$where.should.not.match(/return true/);
                        callback(null, []);
                    }
                };
            };

            allocationsDAO.getByUserIdAndThreshold(userId, maliciousThreshold, function(err, allocations) {
                mockAllocationsCol.find = originalFind;
                done();
            });
        });

        it("should reject non-numeric threshold values", function(done) {
            const userId = "2";
            const maliciousThreshold = "abc";

            try {
                allocationsDAO.getByUserIdAndThreshold(userId, maliciousThreshold, function(err, allocations) {
                    done(new Error("Should have thrown an exception"));
                });
            } catch (e) {
                // Should throw an error due to invalid threshold (NaN)
                e.should.match(/not valid/);
                done();
            }
        });

        it("should reject threshold values below 0", function(done) {
            const userId = "2";
            const invalidThreshold = "-5";

            try {
                allocationsDAO.getByUserIdAndThreshold(userId, invalidThreshold, function(err, allocations) {
                    done(new Error("Should have thrown an exception"));
                });
            } catch (e) {
                // Should throw an error due to invalid threshold
                e.should.match(/not valid/);
                done();
            }
        });

        it("should reject threshold values above 99", function(done) {
            const userId = "2";
            const invalidThreshold = "100";

            try {
                allocationsDAO.getByUserIdAndThreshold(userId, invalidThreshold, function(err, allocations) {
                    done(new Error("Should have thrown an exception"));
                });
            } catch (e) {
                // Should throw an error due to invalid threshold
                e.should.match(/not valid/);
                done();
            }
        });

        it("should accept valid numeric threshold within range (0-99)", function(done) {
            const userId = "2";
            const validThreshold = "50";

            allocationsDAO.getByUserIdAndThreshold(userId, validThreshold, function(err, allocations) {
                // Should not throw an error for valid threshold
                // Note: Will get "No allocations found" error from mock, but that's expected
                if (err && err.indexOf("not valid") !== -1) {
                    done(new Error("Valid threshold was rejected"));
                } else {
                    done();
                }
            });
        });

        it("should accept threshold at lower boundary (0)", function(done) {
            const userId = "2";
            const validThreshold = "0";

            allocationsDAO.getByUserIdAndThreshold(userId, validThreshold, function(err, allocations) {
                // Should not throw an error for valid threshold
                if (err && err.indexOf("not valid") !== -1) {
                    done(new Error("Valid threshold was rejected"));
                } else {
                    done();
                }
            });
        });

        it("should accept threshold at upper boundary (99)", function(done) {
            const userId = "2";
            const validThreshold = "99";

            allocationsDAO.getByUserIdAndThreshold(userId, validThreshold, function(err, allocations) {
                // Should not throw an error for valid threshold
                if (err && err.indexOf("not valid") !== -1) {
                    done(new Error("Valid threshold was rejected"));
                } else {
                    done();
                }
            });
        });
    });

    describe("getByUserIdAndThreshold - Query Construction", function() {

        it("should use parsed integer in $where clause for valid threshold", function(done) {
            const userId = "2";
            const validThreshold = "25";

            // Override toArray to capture the criteria before callback
            const originalFind = mockAllocationsCol.find;
            mockAllocationsCol.find = function(criteria) {
                mockAllocationsCol.lastCriteria = criteria;
                return {
                    toArray: function(callback) {
                        // Verify the criteria uses parsed integer, not raw string
                        should.exist(criteria.$where);
                        // The $where should contain the parsed integer value, not the string with quotes
                        criteria.$where.should.equal("this.userId == 2 && this.stocks > 25");
                        // Ensure no quotes around the threshold value in the query
                        criteria.$where.should.not.match(/'25'/);
                        callback(null, []);
                    }
                };
            };

            allocationsDAO.getByUserIdAndThreshold(userId, validThreshold, function(err, allocations) {
                mockAllocationsCol.find = originalFind;
                done();
            });
        });

        it("should construct safe query without string interpolation of user input", function(done) {
            const userId = "2";
            const validThreshold = "10";

            const originalFind = mockAllocationsCol.find;
            mockAllocationsCol.find = function(criteria) {
                return {
                    toArray: function(callback) {
                        should.exist(criteria.$where);
                        // Verify that the threshold is treated as a number, not a string
                        // This prevents injection because parseInt sanitizes the input
                        const whereClause = criteria.$where;
                        whereClause.should.equal("this.userId == 2 && this.stocks > 10");
                        
                        // Ensure the query doesn't contain any quotes around threshold
                        // which would indicate string interpolation vulnerability
                        whereClause.should.not.match(/'10'/);
                        
                        callback(null, []);
                    }
                };
            };

            allocationsDAO.getByUserIdAndThreshold(userId, validThreshold, function(err, allocations) {
                mockAllocationsCol.find = originalFind;
                done();
            });
        });

        it("should use simple query object when no threshold provided", function(done) {
            const userId = "2";
            const noThreshold = undefined;

            const originalFind = mockAllocationsCol.find;
            mockAllocationsCol.find = function(criteria) {
                return {
                    toArray: function(callback) {
                        // When no threshold, should use simple userId query
                        should.exist(criteria.userId);
                        criteria.userId.should.equal(2);
                        should.not.exist(criteria.$where);
                        callback(null, []);
                    }
                };
            };

            allocationsDAO.getByUserIdAndThreshold(userId, noThreshold, function(err, allocations) {
                mockAllocationsCol.find = originalFind;
                done();
            });
        });
    });

    describe("getByUserIdAndThreshold - Security Properties", function() {

        it("should ensure threshold undergoes parseInt validation before use", function(done) {
            const userId = "2";
            // This would be dangerous if used directly, but parseInt will convert it
            const maliciousThreshold = "5 || true";

            // parseInt("5 || true") returns 5, which is valid
            // The key security property is that the raw string is never interpolated
            const originalFind = mockAllocationsCol.find;
            mockAllocationsCol.find = function(criteria) {
                return {
                    toArray: function(callback) {
                        should.exist(criteria.$where);
                        // Verify only the parsed integer is used
                        criteria.$where.should.equal("this.userId == 2 && this.stocks > 5");
                        // Verify the injection attempt is NOT in the query
                        criteria.$where.should.not.match(/\|\| true/);
                        callback(null, []);
                    }
                };
            };

            allocationsDAO.getByUserIdAndThreshold(userId, maliciousThreshold, function(err, allocations) {
                mockAllocationsCol.find = originalFind;
                done();
            });
        });

        it("should prevent arbitrary JavaScript execution in MongoDB query", function(done) {
            const userId = "2";
            // Classic injection that would execute arbitrary code
            const maliciousThreshold = "1'; db.dropDatabase(); return '1";

            // parseInt will extract "1" from this, making it safe
            const originalFind = mockAllocationsCol.find;
            mockAllocationsCol.find = function(criteria) {
                return {
                    toArray: function(callback) {
                        should.exist(criteria.$where);
                        // Verify the dangerous code was sanitized
                        criteria.$where.should.equal("this.userId == 2 && this.stocks > 1");
                        // Verify the dangerous code is NOT in the query
                        criteria.$where.should.not.match(/dropDatabase/);
                        callback(null, []);
                    }
                };
            };

            allocationsDAO.getByUserIdAndThreshold(userId, maliciousThreshold, function(err, allocations) {
                mockAllocationsCol.find = originalFind;
                done();
            });
        });

        it("should enforce allowlist validation (0-99 range)", function(done) {
            const userId = "2";
            const outOfRangeThreshold = "999";

            try {
                allocationsDAO.getByUserIdAndThreshold(userId, outOfRangeThreshold, function(err, allocations) {
                    done(new Error("Should have thrown an exception"));
                });
            } catch (e) {
                // Should be rejected as out of range
                e.should.match(/not valid/);
                done();
            }
        });
    });
});
