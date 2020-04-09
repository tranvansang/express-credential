"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var ms_1 = __importDefault(require("ms"));
var middleware_async_1 = __importDefault(require("middleware-async"));
var jws_1 = __importDefault(require("jws"));
exports.makeAuthMiddleware = function (encoder, decoder, strategy) { return middleware_async_1.default(function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    var payload, _a;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0:
                req.login = function (user) { return __awaiter(void 0, void 0, void 0, function () {
                    var _a, _b, _c;
                    return __generator(this, function (_d) {
                        switch (_d.label) {
                            case 0:
                                if (!user) return [3 /*break*/, 2];
                                req.user = user;
                                _b = (_a = strategy).setPayload;
                                _c = [req];
                                return [4 /*yield*/, encoder(user)];
                            case 1: return [2 /*return*/, _b.apply(_a, _c.concat([_d.sent()]))];
                            case 2:
                                req.user = undefined;
                                return [4 /*yield*/, strategy.setPayload(req, undefined)];
                            case 3:
                                _d.sent();
                                return [2 /*return*/];
                        }
                    });
                }); };
                req.logout = function () { return __awaiter(void 0, void 0, void 0, function () {
                    return __generator(this, function (_a) {
                        switch (_a.label) {
                            case 0: return [4 /*yield*/, req.login()];
                            case 1:
                                _a.sent();
                                return [2 /*return*/];
                        }
                    });
                }); };
                return [4 /*yield*/, strategy.getPayload(req)];
            case 1:
                payload = _b.sent();
                if (!payload) return [3 /*break*/, 3];
                _a = req;
                return [4 /*yield*/, decoder(payload)];
            case 2:
                _a.user = (_b.sent()) || undefined;
                return [3 /*break*/, 4];
            case 3:
                req.user = undefined;
                _b.label = 4;
            case 4:
                next();
                return [2 /*return*/];
        }
    });
}); }); };
exports.sessionStrategy = function (_a) {
    var _b = _a === void 0 ? {} : _a, _c = _b.expire, expire = _c === void 0 ? ms_1.default('14 days') : _c, _d = _b.key, key = _d === void 0 ? '__auth' : _d;
    return ({
        setPayload: function (req, payload) {
            if (!payload)
                req.session[key] = undefined;
            else
                req.session[key] = {
                    payload: payload,
                    createdAt: new Date().toISOString()
                };
        },
        getPayload: function (req) {
            if (req.session[key]) {
                var _a = req.session[key], payload = _a.payload, createdAt = _a.createdAt;
                if (payload && createdAt) {
                    createdAt = new Date(createdAt);
                    if (!isNaN(createdAt.getTime()) && createdAt.getTime() >= Date.now() - expire)
                        return payload;
                }
                req.session[key] = undefined;
            }
        }
    });
};
exports.jwtStrategy = function (_a) {
    var secret = _a.secret, _b = _a.alg, alg = _b === void 0 ? 'HS256' : _b, _c = _a.expire, expire = _c === void 0 ? ms_1.default('14 days') : _c;
    return ({
        setPayload: function (req, payload) {
            if (payload)
                return jws_1.default.sign({
                    header: { alg: alg },
                    payload: JSON.stringify({
                        payload: payload,
                        createdAt: new Date().toISOString()
                    }),
                    secret: secret
                });
        },
        getPayload: function (req) {
            var _a, _b, _c;
            if ((_b = (_a = req.get('Authentication')) === null || _a === void 0 ? void 0 : _a.startsWith) === null || _b === void 0 ? void 0 : _b.call(_a, 'Bearer ')) {
                var token = req.get('Authentication').replace(/^Bearer /, '');
                try {
                    if (jws_1.default.verify(token, alg, secret)) {
                        var obj = jws_1.default.decode(token);
                        if (obj && ((_c = obj.header) === null || _c === void 0 ? void 0 : _c.alg) === alg) { //after a positive verification, this conditional branch is always positive
                            var _d = JSON.parse(obj.payload), payload = _d.payload, createdAt = _d.createdAt;
                            if (payload && createdAt) {
                                createdAt = new Date(createdAt);
                                if (!isNaN(createdAt.getTime()) && createdAt.getTime() >= Date.now() - expire)
                                    return payload;
                            }
                        }
                    }
                }
                catch (_e) { } //tslint:disable-line:no-empty
            }
        }
    });
};
