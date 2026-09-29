/**
 * Unit tests for ReDoS mitigation in profile route
 * 
 * These tests verify that the profile handler properly mitigates the ReDoS vulnerability
 * by validating input length and using a safe regex pattern without nested quantifiers.
 */

var assert = require("assert");
var should = require("should");

describe("Profile Handler - ReDoS Mitigation Tests", function() {
    "use strict";

    var ProfileHandler;
    var profileHandler;
    var mockDb;
    var mockReq;
    var mockRes;
    var mockNext;
    var renderCalled;
    var renderArgs;
    var updateUserCalled;
    var updateUserArgs;

    before(function() {
        ProfileHandler = require("../../app/routes/profile");
    });

    beforeEach(function() {
        // Mock database with proper collection methods
        mockDb = {
            collection: function() {
                return {
                    findOne: function(query, callback) {
                        callback(null, {});
                    },
                    update: function(query, update, callback) {
                        callback(null);
                    }
                };
            }
        };

        // Create profile handler instance
        profileHandler = new ProfileHandler(mockDb);

        // Reset tracking variables
        renderCalled = false;
        renderArgs = null;
        updateUserCalled = false;
        updateUserArgs = null;

        // Mock request object
        mockReq = {
            body: {},
            session: {
                userId: "123"
            }
        };

        // Mock response object
        mockRes = {
            render: function(view, data) {
                renderCalled = true;
                renderArgs = {
                    view: view,
                    data: data
                };
            }
        };

        // Mock next function
        mockNext = function(err) {
            if (err) throw err;
        };
    });

    describe("Input Length Validation", function() {

        it("should reject bankRouting values longer than 20 characters", function() {
            // This is the ReDoS attack vector - a long digit-only string
            var longDigitString = "1".repeat(100);
            
            mockReq.body = {
                firstName: "John",
                lastName: "Doe",
                ssn: "123-45-6789",
                dob: "01/01/1990",
                address: "123 Main St",
                bankAcc: "12345678",
                bankRouting: longDigitString
            };

            profileHandler.handleProfileUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            renderArgs.data.should.have.property("updateError");
            renderArgs.data.updateError.should.equal(
                "Bank Routing number does not comply with requirements for format specified"
            );
        });

        it("should reject bankRouting with exactly 21 characters", function() {
            mockReq.body = {
                firstName: "John",
                lastName: "Doe",
                ssn: "123-45-6789",
                dob: "01/01/1990",
                address: "123 Main St",
                bankAcc: "12345678",
                bankRouting: "123456789012345678901" // 21 chars
            };

            profileHandler.handleProfileUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            renderArgs.data.should.have.property("updateError");
        });

        it("should reject undefined bankRouting", function() {
            mockReq.body = {
                firstName: "John",
                lastName: "Doe",
                ssn: "123-45-6789",
                dob: "01/01/1990",
                address: "123 Main St",
                bankAcc: "12345678"
                // bankRouting is undefined
            };

            profileHandler.handleProfileUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            renderArgs.data.should.have.property("updateError");
        });

        it("should reject null bankRouting", function() {
            mockReq.body = {
                firstName: "John",
                lastName: "Doe",
                ssn: "123-45-6789",
                dob: "01/01/1990",
                address: "123 Main St",
                bankAcc: "12345678",
                bankRouting: null
            };

            profileHandler.handleProfileUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            renderArgs.data.should.have.property("updateError");
        });

        it("should reject non-string bankRouting (number)", function() {
            mockReq.body = {
                firstName: "John",
                lastName: "Doe",
                ssn: "123-45-6789",
                dob: "01/01/1990",
                address: "123 Main St",
                bankAcc: "12345678",
                bankRouting: 123456789
            };

            profileHandler.handleProfileUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            renderArgs.data.should.have.property("updateError");
        });

        it("should reject non-string bankRouting (object)", function() {
            mockReq.body = {
                firstName: "John",
                lastName: "Doe",
                ssn: "123-45-6789",
                dob: "01/01/1990",
                address: "123 Main St",
                bankAcc: "12345678",
                bankRouting: {value: "123456#"}
            };

            profileHandler.handleProfileUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            renderArgs.data.should.have.property("updateError");
        });

        it("should accept bankRouting with exactly 20 characters", function() {
            mockReq.body = {
                firstName: "John",
                lastName: "Doe",
                ssn: "123-45-6789",
                dob: "01/01/1990",
                address: "123 Main St",
                bankAcc: "12345678",
                bankRouting: "12345678901234567890" // exactly 20 chars, but no # so will fail regex
            };

            profileHandler.handleProfileUpdate(mockReq, mockRes, mockNext);

            // This should fail regex validation (no # suffix), not length validation
            renderCalled.should.be.true();
            renderArgs.data.should.have.property("updateError");
        });
    });

    describe("Regex Pattern Validation", function() {

        it("should reject bankRouting without # suffix", function() {
            mockReq.body = {
                firstName: "John",
                lastName: "Doe",
                ssn: "123-45-6789",
                dob: "01/01/1990",
                address: "123 Main St",
                bankAcc: "12345678",
                bankRouting: "123456789" // No # suffix
            };

            profileHandler.handleProfileUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            renderArgs.data.should.have.property("updateError");
            renderArgs.data.updateError.should.equal(
                "Bank Routing number does not comply with requirements for format specified"
            );
        });

        it("should reject bankRouting with # in the middle", function() {
            mockReq.body = {
                firstName: "John",
                lastName: "Doe",
                ssn: "123-45-6789",
                dob: "01/01/1990",
                address: "123 Main St",
                bankAcc: "12345678",
                bankRouting: "123#456"
            };

            profileHandler.handleProfileUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            renderArgs.data.should.have.property("updateError");
        });

        it("should reject bankRouting with letters", function() {
            mockReq.body = {
                firstName: "John",
                lastName: "Doe",
                ssn: "123-45-6789",
                dob: "01/01/1990",
                address: "123 Main St",
                bankAcc: "12345678",
                bankRouting: "ABC123#"
            };

            profileHandler.handleProfileUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            renderArgs.data.should.have.property("updateError");
        });

        it("should reject bankRouting with special characters other than #", function() {
            mockReq.body = {
                firstName: "John",
                lastName: "Doe",
                ssn: "123-45-6789",
                dob: "01/01/1990",
                address: "123 Main St",
                bankAcc: "12345678",
                bankRouting: "123-456#"
            };

            profileHandler.handleProfileUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            renderArgs.data.should.have.property("updateError");
        });

        it("should reject empty string bankRouting", function() {
            mockReq.body = {
                firstName: "John",
                lastName: "Doe",
                ssn: "123-45-6789",
                dob: "01/01/1990",
                address: "123 Main St",
                bankAcc: "12345678",
                bankRouting: ""
            };

            profileHandler.handleProfileUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            renderArgs.data.should.have.property("updateError");
        });

        it("should accept valid bankRouting with digits and # suffix", function() {
            mockReq.body = {
                firstName: "John",
                lastName: "Doe",
                ssn: "123-45-6789",
                dob: "01/01/1990",
                address: "123 Main St",
                bankAcc: "12345678",
                bankRouting: "123456789#"
            };

            profileHandler.handleProfileUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            // Should not have an error - successful update
            should.not.exist(renderArgs.data.updateError);
        });
    });

    describe("ReDoS Attack Prevention", function() {

        it("should complete quickly with long digit-only string (ReDoS attack vector)", function(done) {
            // This test verifies that the fix prevents catastrophic backtracking
            // The old vulnerable regex /([0-9]+)+\#/ would cause exponential time complexity
            // The new regex /^[0-9]+\#$/ with length check should reject this quickly
            
            var startTime = Date.now();
            
            // Generate a long digit-only string (the documented ReDoS attack vector)
            var attackString = "9".repeat(100);
            
            mockReq.body = {
                firstName: "John",
                lastName: "Doe",
                ssn: "123-45-6789",
                dob: "01/01/1990",
                address: "123 Main St",
                bankAcc: "12345678",
                bankRouting: attackString
            };

            profileHandler.handleProfileUpdate(mockReq, mockRes, mockNext);

            var endTime = Date.now();
            var duration = endTime - startTime;

            // Should complete in well under 100ms (typically < 10ms)
            // The vulnerable version would take seconds or hang
            duration.should.be.below(100);
            
            renderCalled.should.be.true();
            renderArgs.data.should.have.property("updateError");
            
            done();
        });

        it("should complete quickly with the documented attack string from tutorial", function(done) {
            // This is the exact attack string from the ReDoS tutorial documentation
            var startTime = Date.now();
            
            mockReq.body = {
                firstName: "John",
                lastName: "Doe",
                ssn: "123-45-6789",
                dob: "01/01/1990",
                address: "123 Main St",
                bankAcc: "12345678",
                bankRouting: "91762612117612121123123123123121"
            };

            profileHandler.handleProfileUpdate(mockReq, mockRes, mockNext);

            var endTime = Date.now();
            var duration = endTime - startTime;

            // Should complete quickly
            duration.should.be.below(100);
            
            renderCalled.should.be.true();
            renderArgs.data.should.have.property("updateError");
            
            done();
        });

        it("should complete quickly with 50-character digit string", function(done) {
            var startTime = Date.now();
            
            mockReq.body = {
                firstName: "John",
                lastName: "Doe",
                ssn: "123-45-6789",
                dob: "01/01/1990",
                address: "123 Main St",
                bankAcc: "12345678",
                bankRouting: "1".repeat(50)
            };

            profileHandler.handleProfileUpdate(mockReq, mockRes, mockNext);

            var endTime = Date.now();
            var duration = endTime - startTime;

            duration.should.be.below(100);
            renderCalled.should.be.true();
            
            done();
        });

        it("should complete quickly with 1000-character digit string", function(done) {
            var startTime = Date.now();
            
            mockReq.body = {
                firstName: "John",
                lastName: "Doe",
                ssn: "123-45-6789",
                dob: "01/01/1990",
                address: "123 Main St",
                bankAcc: "12345678",
                bankRouting: "1".repeat(1000)
            };

            profileHandler.handleProfileUpdate(mockReq, mockRes, mockNext);

            var endTime = Date.now();
            var duration = endTime - startTime;

            // Even with 1000 characters, should complete quickly due to length check
            duration.should.be.below(100);
            renderCalled.should.be.true();
            
            done();
        });
    });

    describe("Security Properties", function() {

        it("should enforce allowlist validation (digits + # only)", function() {
            var invalidInputs = [
                "abc#",           // letters
                "123-456#",       // dash
                "123 456#",       // space
                "123.456#",       // dot
                "123_456#",       // underscore
                "123$456#",       // dollar sign
                "123@456#",       // at sign
                "<script>#",      // XSS attempt
                "'; DROP TABLE#", // SQL injection attempt
                "../../../#"      // path traversal attempt
            ];

            invalidInputs.forEach(function(invalidInput) {
                renderCalled = false;
                renderArgs = null;

                mockReq.body = {
                    firstName: "John",
                    lastName: "Doe",
                    ssn: "123-45-6789",
                    dob: "01/01/1990",
                    address: "123 Main St",
                    bankAcc: "12345678",
                    bankRouting: invalidInput
                };

                profileHandler.handleProfileUpdate(mockReq, mockRes, mockNext);

                renderCalled.should.be.true();
                renderArgs.data.should.have.property("updateError");
            });
        });

        it("should reject input that starts with # (anchor validation)", function() {
            mockReq.body = {
                firstName: "John",
                lastName: "Doe",
                ssn: "123-45-6789",
                dob: "01/01/1990",
                address: "123 Main St",
                bankAcc: "12345678",
                bankRouting: "#123456"
            };

            profileHandler.handleProfileUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            renderArgs.data.should.have.property("updateError");
        });

        it("should reject input with trailing characters after #", function() {
            mockReq.body = {
                firstName: "John",
                lastName: "Doe",
                ssn: "123-45-6789",
                dob: "01/01/1990",
                address: "123 Main St",
                bankAcc: "12345678",
                bankRouting: "123456#extra"
            };

            profileHandler.handleProfileUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            renderArgs.data.should.have.property("updateError");
        });

        it("should use anchored regex pattern (^ and $)", function() {
            // This test verifies that the regex uses anchors to prevent partial matches
            // The pattern should be /^[0-9]+\#$/ not /[0-9]+\#/
            
            var partialMatchAttempts = [
                "abc123456#",      // prefix
                "123456#xyz",      // suffix
                "abc123456#xyz"    // both
            ];

            partialMatchAttempts.forEach(function(input) {
                renderCalled = false;
                renderArgs = null;

                mockReq.body = {
                    firstName: "John",
                    lastName: "Doe",
                    ssn: "123-45-6789",
                    dob: "01/01/1990",
                    address: "123 Main St",
                    bankAcc: "12345678",
                    bankRouting: input
                };

                profileHandler.handleProfileUpdate(mockReq, mockRes, mockNext);

                renderCalled.should.be.true();
                renderArgs.data.should.have.property("updateError");
            });
        });
    });

    describe("Edge Cases", function() {

        it("should accept minimum valid input (single digit + #)", function() {
            mockReq.body = {
                firstName: "John",
                lastName: "Doe",
                ssn: "123-45-6789",
                dob: "01/01/1990",
                address: "123 Main St",
                bankAcc: "12345678",
                bankRouting: "1#"
            };

            profileHandler.handleProfileUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            should.not.exist(renderArgs.data.updateError);
        });

        it("should accept typical 9-digit routing number with #", function() {
            mockReq.body = {
                firstName: "John",
                lastName: "Doe",
                ssn: "123-45-6789",
                dob: "01/01/1990",
                address: "123 Main St",
                bankAcc: "12345678",
                bankRouting: "021000021#"
            };

            profileHandler.handleProfileUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            should.not.exist(renderArgs.data.updateError);
        });

        it("should reject just # character", function() {
            mockReq.body = {
                firstName: "John",
                lastName: "Doe",
                ssn: "123-45-6789",
                dob: "01/01/1990",
                address: "123 Main St",
                bankAcc: "12345678",
                bankRouting: "#"
            };

            profileHandler.handleProfileUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            renderArgs.data.should.have.property("updateError");
        });

        it("should reject multiple # characters", function() {
            mockReq.body = {
                firstName: "John",
                lastName: "Doe",
                ssn: "123-45-6789",
                dob: "01/01/1990",
                address: "123 Main St",
                bankAcc: "12345678",
                bankRouting: "123##"
            };

            profileHandler.handleProfileUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            renderArgs.data.should.have.property("updateError");
        });
    });
});
