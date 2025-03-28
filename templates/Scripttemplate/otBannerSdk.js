/** 
 * onetrust-banner-sdk
 * v6.35.0
 * by OneTrust LLC
 * Copyright 2022 
 */
!function() {
    "use strict";
    var o = function(e, t) {
        return (o = Object.setPrototypeOf || {
            __proto__: []
        }instanceof Array && function(e, t) {
            e.__proto__ = t
        }
        || function(e, t) {
            for (var o in t)
                t.hasOwnProperty(o) && (e[o] = t[o])
        }
        )(e, t)
    };
    var k, e, r = function() {
        return (r = Object.assign || function(e) {
            for (var t, o = 1, n = arguments.length; o < n; o++)
                for (var r in t = arguments[o])
                    Object.prototype.hasOwnProperty.call(t, r) && (e[r] = t[r]);
            return e
        }
        ).apply(this, arguments)
    };
    function c(i, s, a, l) {
        return new (a = a || Promise)(function(e, t) {
            function o(e) {
                try {
                    r(l.next(e))
                } catch (e) {
                    t(e)
                }
            }
            function n(e) {
                try {
                    r(l.throw(e))
                } catch (e) {
                    t(e)
                }
            }
            function r(t) {
                t.done ? e(t.value) : new a(function(e) {
                    e(t.value)
                }
                ).then(o, n)
            }
            r((l = l.apply(i, s || [])).next())
        }
        )
    }
    function C(o, n) {
        var r, i, s, e, a = {
            label: 0,
            sent: function() {
                if (1 & s[0])
                    throw s[1];
                return s[1]
            },
            trys: [],
            ops: []
        };
        return e = {
            next: t(0),
            throw: t(1),
            return: t(2)
        },
        "function" == typeof Symbol && (e[Symbol.iterator] = function() {
            return this
        }
        ),
        e;
        function t(t) {
            return function(e) {
                return function(t) {
                    if (r)
                        throw new TypeError("Generator is already executing.");
                    for (; a; )
                        try {
                            if (r = 1,
                            i && (s = 2 & t[0] ? i.return : t[0] ? i.throw || ((s = i.return) && s.call(i),
                            0) : i.next) && !(s = s.call(i, t[1])).done)
                                return s;
                            switch (i = 0,
                            s && (t = [2 & t[0], s.value]),
                            t[0]) {
                            case 0:
                            case 1:
                                s = t;
                                break;
                            case 4:
                                return a.label++,
                                {
                                    value: t[1],
                                    done: !1
                                };
                            case 5:
                                a.label++,
                                i = t[1],
                                t = [0];
                                continue;
                            case 7:
                                t = a.ops.pop(),
                                a.trys.pop();
                                continue;
                            default:
                                if (!(s = 0 < (s = a.trys).length && s[s.length - 1]) && (6 === t[0] || 2 === t[0])) {
                                    a = 0;
                                    continue
                                }
                                if (3 === t[0] && (!s || t[1] > s[0] && t[1] < s[3])) {
                                    a.label = t[1];
                                    break
                                }
                                if (6 === t[0] && a.label < s[1]) {
                                    a.label = s[1],
                                    s = t;
                                    break
                                }
                                if (s && a.label < s[2]) {
                                    a.label = s[2],
                                    a.ops.push(t);
                                    break
                                }
                                s[2] && a.ops.pop(),
                                a.trys.pop();
                                continue
                            }
                            t = n.call(o, a)
                        } catch (e) {
                            t = [6, e],
                            i = 0
                        } finally {
                            r = s = 0
                        }
                    if (5 & t[0])
                        throw t[1];
                    return {
                        value: t[0] ? t[1] : void 0,
                        done: !0
                    }
                }([t, e])
            }
        }
    }
    function y() {
        for (var e = 0, t = 0, o = arguments.length; t < o; t++)
            e += arguments[t].length;
        var n = Array(e)
          , r = 0;
        for (t = 0; t < o; t++)
            for (var i = arguments[t], s = 0, a = i.length; s < a; s++,
            r++)
                n[r] = i[s];
        return n
    }
    (e = k = k || {})[e.ACTIVE = 0] = "ACTIVE",
    e[e.ALWAYS_ACTIVE = 1] = "ALWAYS_ACTIVE",
    e[e.EXPIRED = 2] = "EXPIRED",
    e[e.NO_CONSENT = 3] = "NO_CONSENT",
    e[e.OPT_OUT = 4] = "OPT_OUT",
    e[e.PENDING = 5] = "PENDING",
    e[e.WITHDRAWN = 6] = "WITHDRAWN";
    var t = setTimeout;
    function l(e) {
        return Boolean(e && void 0 !== e.length)
    }
    function n() {}
    function i(e) {
        if (!(this instanceof i))
            throw new TypeError("Promises must be constructed via new");
        if ("function" != typeof e)
            throw new TypeError("not a function");
        this._state = 0,
        this._handled = !1,
        this._value = void 0,
        this._deferreds = [],
        h(e, this)
    }
    function s(o, n) {
        for (; 3 === o._state; )
            o = o._value;
        0 !== o._state ? (o._handled = !0,
        i._immediateFn(function() {
            var e = 1 === o._state ? n.onFulfilled : n.onRejected;
            if (null !== e) {
                var t;
                try {
                    t = e(o._value)
                } catch (e) {
                    return void d(n.promise, e)
                }
                a(n.promise, t)
            } else
                (1 === o._state ? a : d)(n.promise, o._value)
        })) : o._deferreds.push(n)
    }
    function a(t, e) {
        try {
            if (e === t)
                throw new TypeError("A promise cannot be resolved with itself.");
            if (e && ("object" == typeof e || "function" == typeof e)) {
                var o = e.then;
                if (e instanceof i)
                    return t._state = 3,
                    t._value = e,
                    void u(t);
                if ("function" == typeof o)
                    return void h((n = o,
                    r = e,
                    function() {
                        n.apply(r, arguments)
                    }
                    ), t)
            }
            t._state = 1,
            t._value = e,
            u(t)
        } catch (e) {
            d(t, e)
        }
        var n, r
    }
    function d(e, t) {
        e._state = 2,
        e._value = t,
        u(e)
    }
    function u(e) {
        2 === e._state && 0 === e._deferreds.length && i._immediateFn(function() {
            e._handled || i._unhandledRejectionFn(e._value)
        });
        for (var t = 0, o = e._deferreds.length; t < o; t++)
            s(e, e._deferreds[t]);
        e._deferreds = null
    }
    function p(e, t, o) {
        this.onFulfilled = "function" == typeof e ? e : null,
        this.onRejected = "function" == typeof t ? t : null,
        this.promise = o
    }
    function h(e, t) {
        var o = !1;
        try {
            e(function(e) {
                o || (o = !0,
                a(t, e))
            }, function(e) {
                o || (o = !0,
                d(t, e))
            })
        } catch (e) {
            if (o)
                return;
            o = !0,
            d(t, e)
        }
    }
    function g() {}
    i.prototype.catch = function(e) {
        return this.then(null, e)
    }
    ,
    i.prototype.then = function(e, t) {
        var o = new this.constructor(n);
        return s(this, new p(e,t,o)),
        o
    }
    ,
    i.prototype.finally = function(t) {
        var o = this.constructor;
        return this.then(function(e) {
            return o.resolve(t()).then(function() {
                return e
            })
        }, function(e) {
            return o.resolve(t()).then(function() {
                return o.reject(e)
            })
        })
    }
    ,
    i.all = function(t) {
        return new i(function(n, r) {
            if (!l(t))
                return r(new TypeError("Promise.all accepts an array"));
            var i = Array.prototype.slice.call(t);
            if (0 === i.length)
                return n([]);
            var s = i.length;
            function a(t, e) {
                try {
                    if (e && ("object" == typeof e || "function" == typeof e)) {
                        var o = e.then;
                        if ("function" == typeof o)
                            return void o.call(e, function(e) {
                                a(t, e)
                            }, r)
                    }
                    i[t] = e,
                    0 == --s && n(i)
                } catch (e) {
                    r(e)
                }
            }
            for (var e = 0; e < i.length; e++)
                a(e, i[e])
        }
        )
    }
    ,
    i.resolve = function(t) {
        return t && "object" == typeof t && t.constructor === i ? t : new i(function(e) {
            e(t)
        }
        )
    }
    ,
    i.reject = function(o) {
        return new i(function(e, t) {
            t(o)
        }
        )
    }
    ,
    i.race = function(r) {
        return new i(function(e, t) {
            if (!l(r))
                return t(new TypeError("Promise.race accepts an array"));
            for (var o = 0, n = r.length; o < n; o++)
                i.resolve(r[o]).then(e, t)
        }
        )
    }
    ,
    i._immediateFn = "function" == typeof setImmediate ? function(e) {
        setImmediate(e)
    }
    : function(e) {
        t(e, 0)
    }
    ,
    i._unhandledRejectionFn = function(e) {
        "undefined" != typeof console && console && console.warn("Possible Unhandled Promise Rejection:", e)
    }
    ;
    var f, v, m, b, P, S, A, T, G, I, E, L, _, V, B, w, x, O, W, N, D, H, F, R, q, M, U, j, z, K, J, Y, X, Q, $, Z, ee, te, oe, ne, re, ie, se, ae, le, ce, de, ue, pe, he, ge, Ce, ye, fe, ve, ke, me, be, Pe, Se = new (g.prototype.initPolyfill = function() {
        this.initArrayIncludesPolyfill(),
        this.initObjectAssignPolyfill(),
        this.initArrayFillPolyfill(),
        this.initClosestPolyfill(),
        this.initIncludesPolyfill(),
        this.initEndsWithPoly(),
        this.initCustomEventPolyfill(),
        this.promisesPolyfil()
    }
    ,
    g.prototype.initArrayIncludesPolyfill = function() {
        Array.prototype.includes || Object.defineProperty(Array.prototype, "includes", {
            value: function(e) {
                for (var t = [], o = 1; o < arguments.length; o++)
                    t[o - 1] = arguments[o];
                if (null == this)
                    throw new TypeError("Array.prototype.includes called on null or undefined");
                var n = Object(this)
                  , r = parseInt(n.length, 10) || 0;
                if (0 === r)
                    return !1;
                var i, s, a = t[1] || 0;
                for (0 <= a ? i = a : (i = r + a) < 0 && (i = 0); i < r; ) {
                    if (e === (s = n[i]) || e != e && s != s)
                        return !0;
                    i++
                }
                return !1
            },
            writable: !0,
            configurable: !0
        })
    }
    ,
    g.prototype.initEndsWithPoly = function() {
        String.prototype.endsWith || Object.defineProperty(String.prototype, "endsWith", {
            value: function(e, t) {
                return (void 0 === t || t > this.length) && (t = this.length),
                this.substring(t - e.length, t) === e
            },
            writable: !0,
            configurable: !0
        })
    }
    ,
    g.prototype.initClosestPolyfill = function() {
        Element.prototype.matches || (Element.prototype.matches = Element.prototype.msMatchesSelector || Element.prototype.webkitMatchesSelector),
        Element.prototype.closest || Object.defineProperty(Element.prototype, "closest", {
            value: function(e) {
                var t = this;
                do {
                    if (t.matches(e))
                        return t;
                    t = t.parentElement || t.parentNode
                } while (null !== t && 1 === t.nodeType);
                return null
            },
            writable: !0,
            configurable: !0
        })
    }
    ,
    g.prototype.initIncludesPolyfill = function() {
        String.prototype.includes || Object.defineProperty(String.prototype, "includes", {
            value: function(e, t) {
                return "number" != typeof t && (t = 0),
                !(t + e.length > this.length) && -1 !== this.indexOf(e, t)
            },
            writable: !0,
            configurable: !0
        })
    }
    ,
    g.prototype.initObjectAssignPolyfill = function() {
        "function" != typeof Object.assign && Object.defineProperty(Object, "assign", {
            value: function(e, t) {
                if (null == e)
                    throw new TypeError("Cannot convert undefined or null to object");
                for (var o = Object(e), n = 1; n < arguments.length; n++) {
                    var r = arguments[n];
                    if (null != r)
                        for (var i in r)
                            Object.prototype.hasOwnProperty.call(r, i) && (o[i] = r[i])
                }
                return o
            },
            writable: !0,
            configurable: !0
        })
    }
    ,
    g.prototype.initArrayFillPolyfill = function() {
        Array.prototype.fill || Object.defineProperty(Array.prototype, "fill", {
            value: function(e) {
                if (null == this)
                    throw new TypeError("this is null or not defined");
                for (var t = Object(this), o = t.length >>> 0, n = arguments[1] >> 0, r = n < 0 ? Math.max(o + n, 0) : Math.min(n, o), i = arguments[2], s = void 0 === i ? o : i >> 0, a = s < 0 ? Math.max(o + s, 0) : Math.min(s, o); r < a; )
                    t[r] = e,
                    r++;
                return t
            }
        })
    }
    ,
    g.prototype.initCustomEventPolyfill = function() {
        if ("function" == typeof window.CustomEvent)
            return !1;
        function e(e, t) {
            t = t || {
                bubbles: !1,
                cancelable: !1,
                detail: void 0
            };
            var o = document.createEvent("CustomEvent");
            return o.initCustomEvent(e, t.bubbles, t.cancelable, t.detail),
            o
        }
        e.prototype = window.Event.prototype,
        window.CustomEvent = e
    }
    ,
    g.prototype.insertViewPortTag = function() {
        var e = document.querySelector('meta[name="viewport"]')
          , t = document.createElement("meta");
        t.name = "viewport",
        t.content = "width=device-width, initial-scale=1",
        e || document.head.appendChild(t)
    }
    ,
    g.prototype.promisesPolyfil = function() {
        "undefined" == typeof Promise && (window.Promise = i)
    }
    ,
    g);
    (v = f = f || {})[v.Unknown = 0] = "Unknown",
    v[v.BannerCloseButton = 1] = "BannerCloseButton",
    v[v.ConfirmChoiceButton = 2] = "ConfirmChoiceButton",
    v[v.AcceptAll = 3] = "AcceptAll",
    v[v.RejectAll = 4] = "RejectAll",
    v[v.BannerSaveSettings = 5] = "BannerSaveSettings",
    v[v.ContinueWithoutAcceptingButton = 6] = "ContinueWithoutAcceptingButton",
    (b = m = m || {})[b.Banner = 1] = "Banner",
    b[b.PC = 2] = "PC",
    b[b.API = 3] = "API",
    (S = P = P || {}).AcceptAll = "AcceptAll",
    S.RejectAll = "RejectAll",
    S.UpdateConsent = "UpdateConsent",
    (T = A = A || {})[T.Purpose = 1] = "Purpose",
    T[T.SpecialFeature = 2] = "SpecialFeature",
    (I = G = G || {}).Legal = "legal",
    I.UserFriendly = "user_friendly",
    (L = E = E || {}).Top = "top",
    L.Bottom = "bottom",
    (V = _ = _ || {})[V.Banner = 0] = "Banner",
    V[V.PrefCenterHome = 1] = "PrefCenterHome",
    V[V.VendorList = 2] = "VendorList",
    V[V.CookieList = 3] = "CookieList",
    (w = B = B || {})[w.RightArrow = 39] = "RightArrow",
    w[w.LeftArrow = 37] = "LeftArrow",
    (O = x = x || {}).AfterTitle = "AfterTitle",
    O.AfterDescription = "AfterDescription",
    O.AfterDPD = "AfterDPD",
    (N = W = W || {}).PlusMinus = "Plusminus",
    N.Caret = "Caret",
    N.NoAccordion = "NoAccordion",
    (H = D = D || {}).Consent = "Consent",
    H.LI = "LI",
    H.AddtlConsent = "AddtlConsent",
    (R = F = F || {}).Iab1Pub = "eupubconsent",
    R.Iab2Pub = "eupubconsent-v2",
    R.Iab1Eu = "euconsent",
    R.Iab2Eu = "euconsent-v2",
    (M = q = q || {})[M.Disabled = 0] = "Disabled",
    M[M.Consent = 1] = "Consent",
    M[M.LegInt = 2] = "LegInt",
    (j = U = U || {})[j["Banner - Allow All"] = 1] = "Banner - Allow All",
    j[j["Banner - Reject All"] = 2] = "Banner - Reject All",
    j[j["Banner - Close"] = 3] = "Banner - Close",
    j[j["Preference Center - Allow All"] = 4] = "Preference Center - Allow All",
    j[j["Preference Center - Reject All"] = 5] = "Preference Center - Reject All",
    j[j["Preference Center - Confirm"] = 6] = "Preference Center - Confirm",
    (K = z = z || {}).Active = "1",
    K.InActive = "0",
    (Y = J = J || {}).Host = "Host",
    Y.GenVendor = "GenVen",
    (Q = X = X || {})[Q.Host = 1] = "Host",
    Q[Q.GenVen = 2] = "GenVen",
    Q[Q.HostAndGenVen = 3] = "HostAndGenVen",
    (Z = $ = $ || {})[Z.minDays = 1] = "minDays",
    Z[Z.maxDays = 30] = "maxDays",
    Z[Z.maxYear = 31536e3] = "maxYear",
    Z[Z.maxSecToDays = 86400] = "maxSecToDays",
    (te = ee = ee || {})[te.RTL = 0] = "RTL",
    te[te.LTR = 1] = "LTR",
    (ne = oe = oe || {})[ne.GoogleVendor = 1] = "GoogleVendor",
    ne[ne.GeneralVendor = 2] = "GeneralVendor",
    (ie = re = re || {})[ie.Days = 1] = "Days",
    ie[ie.Weeks = 7] = "Weeks",
    ie[ie.Months = 30] = "Months",
    ie[ie.Years = 365] = "Years",
    (ae = se = se || {}).Checkbox = "Checkbox",
    ae.Toggle = "Toggle",
    (ce = le = le || {}).SlideIn = "Slide_In",
    ce.FadeIn = "Fade_In",
    ce.RemoveAnimation = "Remove_Animation",
    (ue = de = de || {}).Link = "Link",
    ue.Icon = "Icon",
    (he = pe = pe || {}).consent = "consent",
    he.set = "set",
    (Ce = ge = ge || {}).update = "update",
    Ce.default = "default",
    Ce.ads_data_redaction = "ads_data_redaction",
    (fe = ye = ye || {}).analytics_storage = "analytics_storage",
    fe.ad_storage = "ad_storage",
    fe.functionality_storage = "functionality_storage",
    fe.personalization_storage = "personalization_storage",
    fe.security_storage = "security_storage",
    fe.region = "region",
    fe.wait_for_update = "wait_for_update",
    (ke = ve = ve || {}).granted = "granted",
    ke.denied = "denied",
    (be = me = me || {})[be.HostList = 0] = "HostList",
    be[be.IabVendors = 1] = "IabVendors",
    be[be.VendorServices = 2] = "VendorServices";
    var Ae = "AwaitingReconsent"
      , Te = "consentId"
      , Ie = "geolocation"
      , Le = "interactionCount"
      , _e = "isIABGlobal"
      , Ve = "NotLandingPage"
      , Be = "isGpcEnabled"
      , Ee = {
        ADDITIONAL_CONSENT_STRING: "OTAdditionalConsentString",
        ALERT_BOX_CLOSED: "OptanonAlertBoxClosed",
        OPTANON_CONSENT: "OptanonConsent",
        EU_PUB_CONSENT: "eupubconsent-v2",
        EU_CONSENT: "euconsent-v2",
        SELECTED_VARIANT: "OTVariant",
        OT_PREVIEW: "otpreview"
    }
      , we = "CONFIRMED"
      , xe = "OPT_OUT"
      , Ge = "NO_CHOICE"
      , Oe = "NOTGIVEN"
      , Ne = "NO_OPT_OUT"
      , De = "always active"
      , He = "active"
      , Fe = "inactive landingpage"
      , Re = "inactive"
      , qe = "dnt"
      , Me = "LOCAL"
      , Ue = "TEST"
      , je = "LOCAL_TEST"
      , ze = "data-language"
      , Ke = "otCookieSettingsButton.json"
      , We = "otCookieSettingsButtonRtl.json"
      , Je = "otCenterRounded"
      , Ye = "otFlat"
      , Xe = "otFloatingRoundedCorner"
      , Qe = "otFloatingFlat"
      , $e = "otFloatingRoundedIcon"
      , Ze = "otFloatingRounded"
      , et = "otChoicesBanner"
      , tt = "otNoBanner"
      , ot = "otPcCenter"
      , nt = "otPcList"
      , rt = "otPcPanel"
      , it = "otPcPopup"
      , st = "otPcTab"
      , at = "hidebanner"
      , lt = ((Pe = {})[re.Days] = "PCenterVendorListLifespanDay",
    Pe[re.Weeks] = "LfSpnWk",
    Pe[re.Months] = "PCenterVendorListLifespanMonth",
    Pe[re.Years] = "LfSpnYr",
    Pe)
      , ct = "DNAC"
      , dt = "Category"
      , ut = "Host"
      , pt = "General Vendor"
      , ht = "VendorService"
      , gt = "BRANCH"
      , Ct = "COOKIE"
      , yt = "IAB2_FEATURE"
      , ft = "IAB2_PURPOSE"
      , vt = "IAB2_SPL_FEATURE"
      , kt = "IAB2_SPL_PURPOSE"
      , mt = "IAB2_STACK"
      , bt = ["IAB2_PURPOSE", "IAB2_STACK", "IAB2_FEATURE", "IAB2_SPL_PURPOSE", "IAB2_SPL_FEATURE"]
      , Pt = ["COOKIE", "BRANCH", "IAB2_STACK"]
      , St = ["IAB2_PURPOSE", "IAB2_SPL_FEATURE"]
      , At = ["IAB2_FEATURE", "IAB2_SPL_PURPOSE"]
      , Tt = ["IAB2_PURPOSE", "IAB2_SPL_PURPOSE", "IAB2_FEATURE", "IAB2_SPL_FEATURE"]
      , It = new function() {}
    ;
    function Lt(e, t, o) {
        void 0 === o && (o = !1);
        function n(e) {
            if (!e)
                return null;
            var t = e.trim();
            return ";" !== t.charAt(t.length - 1) && (t += ";"),
            t.trim()
        }
        var i = n(e.getAttribute("style"))
          , s = n(t)
          , r = "";
        r = o && i ? function() {
            for (var e = i.split(";").concat(s.split(";")).filter(function(e) {
                return 0 !== e.length
            }), t = "", o = "", n = e.length - 1; 0 <= n; n--) {
                var r = e[n].substring(0, e[n].indexOf(":")).trim();
                t.indexOf(r) < 0 && (t += r,
                o += e[n] + ";")
            }
            return o
        }() : s,
        e.setAttribute("style", r)
    }
    function _t() {}
    var Vt, Bt = new (_t.prototype.convertKeyValueLowerCase = function(e) {
        for (var t in e)
            e[t.toLowerCase()] ? e[t.toLowerCase()] = e[t].toLowerCase() : (e[t] && (e[t.toLowerCase()] = e[t].toLowerCase()),
            delete e[t]);
        return e
    }
    ,
    _t.prototype.arrToStr = function(e) {
        return e.toString()
    }
    ,
    _t.prototype.strToArr = function(e) {
        return e ? e.split(",") : []
    }
    ,
    _t.prototype.strToMap = function(e) {
        if (!e)
            return new Map;
        for (var t = new Map, o = 0, n = this.strToArr(e); o < n.length; o++) {
            var r = n[o].split(":");
            t.set(r[0], "1" === r[1])
        }
        return t
    }
    ,
    _t.prototype.empty = function(e) {
        var t = document.getElementById(e);
        if (t)
            for (; t.hasChildNodes(); )
                t.removeChild(t.lastChild)
    }
    ,
    _t.prototype.show = function(e) {
        var t = document.getElementById(e);
        t && Lt(t, "display: block;", !0)
    }
    ,
    _t.prototype.remove = function(e) {
        var t = document.getElementById(e);
        t && t.parentNode && t.parentNode.removeChild(t)
    }
    ,
    _t.prototype.appendTo = function(e, t) {
        var o, n = document.getElementById(e);
        n && ((o = document.createElement("div")).innerHTML = t,
        n.appendChild(o))
    }
    ,
    _t.prototype.contains = function(e, t) {
        var o;
        for (o = 0; o < e.length; o += 1)
            if (e[o].toString().toLowerCase() === t.toString().toLowerCase())
                return !0;
        return !1
    }
    ,
    _t.prototype.indexOf = function(e, t) {
        var o;
        for (o = 0; o < e.length; o += 1)
            if (e[o] === t)
                return o;
        return -1
    }
    ,
    _t.prototype.endsWith = function(e, t) {
        return -1 !== e.indexOf(t, e.length - t.length)
    }
    ,
    _t.prototype.generateUUID = function() {
        var o = (new Date).getTime();
        return "undefined" != typeof performance && "function" == typeof performance.now && (o += performance.now()),
        "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function(e) {
            var t = (o + 16 * Math.random()) % 16 | 0;
            return o = Math.floor(o / 16),
            ("x" === e ? t : 3 & t | 8).toString(16)
        })
    }
    ,
    _t.prototype.getActiveIdArray = function(e) {
        return e.filter(function(e) {
            return "true" === e.split(":")[1]
        }).map(function(e) {
            return parseInt(e.split(":")[0])
        })
    }
    ,
    _t.prototype.distinctArray = function(e) {
        var t = new Array;
        return e.forEach(function(e) {
            t.indexOf(e) < 0 && t.push(e)
        }),
        t
    }
    ,
    _t.prototype.findIndex = function(e, t) {
        for (var o = -1, n = 0; n < e.length; n++)
            if (void 0 !== e[n] && t(e[n], n)) {
                o = n;
                break
            }
        return o
    }
    ,
    _t.prototype.getURL = function(e) {
        var t = document.createElement("a");
        return t.href = e,
        t
    }
    ,
    _t.prototype.removeURLPrefixes = function(e) {
        return e.toLowerCase().replace(/(^\w+:|^)\/\//, "").replace("www.", "")
    }
    ,
    _t.prototype.removeChild = function(e) {
        if (e)
            if (e instanceof NodeList || e instanceof Array)
                for (var t = 0; t < e.length; t++)
                    e[t].parentElement.removeChild(e[t]);
            else
                e.parentElement.removeChild(e)
    }
    ,
    _t.prototype.getRelativeURL = function(e, t, o) {
        if (void 0 === o && (o = !1),
        t) {
            var n = "./" + e.replace(/^(http|https):\/\//, "").split("/").slice(1).join("/").replace(".json", "");
            return o ? n : n + ".js"
        }
        return e
    }
    ,
    _t.prototype.setCheckedAttribute = function(e, t, o) {
        e && (t = document.querySelector(e)),
        t && (t.setAttribute("aria-checked", o.toString()),
        o ? t.setAttribute("checked", "") : t.removeAttribute("checked"),
        t.checked = o)
    }
    ,
    _t.prototype.setDisabledAttribute = function(e, t, o) {
        e && (t = document.querySelector(e)),
        t && (o ? t.setAttribute("disabled", o.toString()) : t.removeAttribute("disabled"))
    }
    ,
    _t.prototype.setHtmlAttributes = function(e, t) {
        for (var o in t)
            e.setAttribute(o, t[o]),
            e[o] = t[o]
    }
    ,
    _t.prototype.calculateCookieLifespan = function(e) {
        if (e < 0)
            return Nt.LifespanTypeText;
        var t = Math.floor(e / $.maxSecToDays);
        if (t < $.minDays)
            return "< 1 " + Nt.PCenterVendorListLifespanDay;
        if (t < $.maxDays)
            return t + " " + Nt.PCenterVendorListLifespanDays;
        var o = Math.floor(t / $.maxDays);
        return 1 === o ? o + " " + Nt.PCenterVendorListLifespanMonth : o + " " + Nt.PCenterVendorListLifespanMonths
    }
    ,
    _t.prototype.insertElement = function(e, t, o) {
        e && t && e.insertAdjacentElement(o, t)
    }
    ,
    _t.prototype.customQuerySelector = function(t) {
        return function(e) {
            return t.querySelector(e)
        }
    }
    ,
    _t.prototype.customQuerySelectorAll = function(t) {
        return function(e) {
            return t.querySelectorAll(e)
        }
    }
    ,
    _t), Et = (wt.prototype.removeAlertBox = function() {
        null !== this.getCookie(Ee.ALERT_BOX_CLOSED) && this.setCookie(Ee.ALERT_BOX_CLOSED, "", 0, !0)
    }
    ,
    wt.prototype.removeIab1 = function() {
        null !== this.getCookie(F.Iab1Pub) && this.setCookie(F.Iab1Pub, "", 0, !0)
    }
    ,
    wt.prototype.removeIab2 = function() {
        null !== this.getCookie(F.Iab2Pub) && this.setCookie(F.Iab2Pub, "", 0, !0)
    }
    ,
    wt.prototype.removeAddtlStr = function() {
        null !== this.getCookie(Ee.ADDITIONAL_CONSENT_STRING) && this.setCookie(Ee.ADDITIONAL_CONSENT_STRING, "", 0, !0)
    }
    ,
    wt.prototype.removeVariant = function() {
        null !== this.getCookie(Ee.SELECTED_VARIANT) && this.setCookie(Ee.SELECTED_VARIANT, "", 0, !0)
    }
    ,
    wt.prototype.removeOptanon = function() {
        null !== this.getCookie(Ee.OPTANON_CONSENT) && this.setCookie(Ee.OPTANON_CONSENT, "", 0, !0)
    }
    ,
    wt.prototype.removePreview = function() {
        null !== this.getCookie(Ee.OT_PREVIEW) && this.setCookie(Ee.OT_PREVIEW, "", 0, !0)
    }
    ,
    wt.prototype.writeCookieParam = function(e, t, o, n) {
        var r, i, s, a, l = {}, c = this.getCookie(e);
        if (c)
            for (i = c.split("&"),
            r = 0; r < i.length; r += 1)
                s = i[r].split("="),
                l[decodeURIComponent(s[0])] = s[0] === t && n ? decodeURIComponent(s[1]) : decodeURIComponent(s[1]).replace(/\+/g, " ");
        l[t] = o;
        var d = It.moduleInitializer.TenantFeatures;
        d && d.CookieV2CookieDateTimeInISO ? l.datestamp = (new Date).toISOString() : l.datestamp = (new Date).toString(),
        l.version = Ht.otSDKVersion,
        a = this.param(l),
        this.setCookie(e, a, Nt.ReconsentFrequencyDays)
    }
    ,
    wt.prototype.readCookieParam = function(e, t, o) {
        var n, r, i, s, a = this.getCookie(e);
        if (a) {
            for (r = {},
            i = a.split("&"),
            n = 0; n < i.length; n += 1)
                s = i[n].split("="),
                r[decodeURIComponent(s[0])] = o ? decodeURIComponent(s[1]) : decodeURIComponent(s[1]).replace(/\+/g, " ");
            return t && r[t] ? r[t] : t && !r[t] ? "" : r
        }
        return ""
    }
    ,
    wt.prototype.getCookie = function(e) {
        if (It && It.moduleInitializer && It.moduleInitializer.MobileSDK) {
            var t = this.getCookieDataObj(e);
            if (t)
                return t.value
        }
        if (Ht.isAMP && (Ht.ampData = JSON.parse(localStorage.getItem(Ht.dataDomainId)) || {},
        Ht.ampData))
            return Ht.ampData[e] || null;
        var o, n, r = e + "=", i = document.cookie.split(";");
        for (o = 0; o < i.length; o += 1) {
            for (n = i[o]; " " === n.charAt(0); )
                n = n.substring(1, n.length);
            if (0 === n.indexOf(r))
                return n.substring(r.length, n.length)
        }
        return null
    }
    ,
    wt.prototype.setAmpStorage = function() {
        window.localStorage.setItem(Ht.dataDomainId, JSON.stringify(Ht.ampData))
    }
    ,
    wt.prototype.removeAmpStorage = function() {
        window.localStorage.removeItem(Ht.dataDomainId)
    }
    ,
    wt.prototype.handleAmp = function(e, t) {
        "" !== t ? Ht.ampData[e] = t : delete Ht.ampData[e],
        0 === Object.keys(Ht.ampData).length ? this.removeAmpStorage() : this.setAmpStorage()
    }
    ,
    wt.prototype.setCookie = function(e, t, o, n, r) {
        if (void 0 === n && (n = !1),
        void 0 === r && (r = new Date),
        Ht.isAMP)
            this.handleAmp(e, t);
        else {
            var i = void 0;
            i = o ? (r.setTime(r.getTime() + 24 * o * 60 * 60 * 1e3),
            "; expires=" + r.toUTCString()) : n ? "; expires=" + new Date(0).toUTCString() : "";
            var s = It.moduleInitializer
              , a = s && s.Domain ? s.Domain.split("/") : []
              , l = ""
              , c = s.TenantFeatures;
            a.length <= 1 ? a[1] = "" : l = a.slice(1).join("/");
            var d = "Samesite=Lax";
            c && c.CookiesSameSiteNone && (d = "Samesite=None; Secure");
            var u = s.ScriptType === Ue || s.ScriptType === je;
            if (Ht.isPreview || !u && !s.MobileSDK)
                p = t + i + "; path=/" + l + "; domain=." + a[0] + "; " + d,
                document.cookie = e + "=" + p;
            else {
                var p = t + i + "; path=/; " + d;
                s.MobileSDK ? this.setCookieDataObj({
                    name: e,
                    value: t,
                    expires: i,
                    date: r,
                    domainAndPath: a
                }) : document.cookie = e + "=" + p
            }
        }
    }
    ,
    wt.prototype.setCookieDataObj = function(t) {
        if (t) {
            Ht.otCookieData || (window.OneTrust && window.OneTrust.otCookieData ? Ht.otCookieData = window.OneTrust.otCookieData : Ht.otCookieData = []);
            var e = Bt.findIndex(Ht.otCookieData, function(e) {
                return e.name === t.name
            });
            -1 < e ? Ht.otCookieData[e] = t : Ht.otCookieData.push(t)
        }
    }
    ,
    wt.prototype.getCookieDataObj = function(t) {
        Ht.otCookieData && 0 !== Ht.otCookieData.length || (window.OneTrust && window.OneTrust.otCookieData ? Ht.otCookieData = window.OneTrust.otCookieData : Ht.otCookieData = []);
        var e = Bt.findIndex(Ht.otCookieData, function(e) {
            return e.name === t
        });
        if (0 <= e) {
            var o = Ht.otCookieData[e];
            if (o.date)
                return new Date(o.date) < new Date ? (Ht.otCookieData.splice(e, 1),
                null) : o
        }
        return null
    }
    ,
    wt.prototype.param = function(e) {
        var t, o = "";
        for (t in e)
            e.hasOwnProperty(t) && ("" !== o && (o += "&"),
            o += t + "=" + encodeURIComponent(e[t]).replace(/%20/g, "+"));
        return o
    }
    ,
    wt);
    function wt() {}
    var xt = (Gt.prototype.setRegionRule = function(e) {
        this.rule = e
    }
    ,
    Gt.prototype.getRegionRule = function() {
        return this.rule
    }
    ,
    Gt.prototype.getRegionRuleType = function() {
        return this.multiVariantTestingEnabled && this.selectedVariant ? this.selectedVariant.TemplateType : this.conditionalLogicEnabled && !this.allConditionsFailed ? this.Condition.TemplateType : this.rule.Type
    }
    ,
    Gt.prototype.canUseGoogleVendors = function(e) {
        return !!e && (this.conditionalLogicEnabled && !this.allConditionsFailed ? this.Condition.UseGoogleVendors : this.rule.UseGoogleVendors)
    }
    ,
    Gt.prototype.initVariables = function() {
        this.consentableGrps = [],
        this.consentableIabGrps = [],
        this.iabGrps = [],
        this.iabGrpIdMap = {},
        this.domainGrps = {},
        this.iabGroups = {
            purposes: {},
            legIntPurposes: {},
            specialPurposes: {},
            features: {},
            specialFeatures: {}
        }
    }
    ,
    Gt.prototype.init = function(e) {
        this.getGPCSignal(),
        this.initVariables();
        var t = e.DomainData;
        this.setPublicDomainData(JSON.parse(JSON.stringify(t))),
        this.domainDataMapper(t),
        this.commonDataMapper(e.CommonData),
        Nt.NtfyConfig = e.NtfyConfig || {},
        this.setBannerName(),
        this.setPcName(),
        this.populateGPCSignal(),
        Nt.GoogleConsent.GCEnable && this.initGCM()
    }
    ,
    Gt.prototype.getGPCSignal = function() {
        this.gpcEnabled = !0 === navigator.globalPrivacyControl
    }
    ,
    Gt.prototype.isValidConsentNoticeGroup = function(e, t) {
        if (!e.ShowInPopup)
            return !1;
        var o = e.FirstPartyCookies.length || e.Hosts.length || e.GeneralVendorsIds && e.GeneralVendorsIds.length || e.VendorServices && e.VendorServices.length
          , n = !1
          , r = !1
          , i = !1;
        if (e && !e.Parent) {
            e.SubGroups.length && (n = e.SubGroups.some(function(e) {
                return e.GroupName && e.ShowInPopup && e.FirstPartyCookies.length
            }),
            r = e.SubGroups.some(function(e) {
                return e.GroupName && e.ShowInPopup && (e.Hosts.length || e.GeneralVendorsIds && e.GeneralVendorsIds.length)
            }),
            !t || e.FirstPartyCookies.length && e.Hosts.length || (i = !e.SubGroups.some(function(e) {
                return -1 === bt.indexOf(e.Type)
            })));
            var s = e.SubGroups.some(function(e) {
                return -1 < bt.indexOf(e.Type)
            });
            (-1 < bt.indexOf(e.Type) || s) && (e.ShowVendorList = !0),
            (e.Hosts.length || r || n) && (e.ShowHostList = !0)
        }
        return o || -1 < bt.indexOf(e.Type) || n || r || i
    }
    ,
    Gt.prototype.extractGroupIdForIabGroup = function(e) {
        return -1 < e.indexOf("ISPV2_") ? e = e.replace("ISPV2_", "") : -1 < e.indexOf("IABV2_") ? e = e.replace("IABV2_", "") : -1 < e.indexOf("IFEV2_") ? e = e.replace("IFEV2_", "") : -1 < e.indexOf("ISFV2_") && (e = e.replace("ISFV2_", "")),
        e
    }
    ,
    Gt.prototype.populateGroups = function(e, r) {
        var i = this
          , s = {}
          , a = [];
        e.forEach(function(e) {
            var t = e.CustomGroupId;
            if (void 0 !== e.HasConsentOptOut && e.IsIabPurpose || (e.HasConsentOptOut = !0),
            !(!r.IsIabEnabled && -1 < bt.indexOf(e.Type) || "IAB2" === i.iabType && (e.Type === ft || e.Type === mt) && !e.HasConsentOptOut && !e.HasLegIntOptOut || e.Type === vt && !e.HasConsentOptOut) && (t !== Ot.purposeOneGrpId || e.ShowInPopup || (i.purposeOneTreatment = !0),
            i.grpContainLegalOptOut = e.HasLegIntOptOut || i.grpContainLegalOptOut,
            e.SubGroups = [],
            e.Parent ? a.push(e) : s[t] = e,
            "IAB2" === i.iabType && -1 < bt.indexOf(e.Type))) {
                var o = i.extractGroupIdForIabGroup(t);
                i.iabGrpIdMap[t] = o,
                e.IabGrpId = o;
                var n = {
                    description: e.GroupDescription,
                    descriptionLegal: e.DescriptionLegal,
                    id: Number(o),
                    name: e.GroupName
                };
                switch (e.Type) {
                case ft:
                    i.iabGroups.purposes[o] = n;
                    break;
                case kt:
                    i.iabGroups.specialPurposes[o] = n;
                    break;
                case yt:
                    i.iabGroups.features[o] = n;
                    break;
                case vt:
                    i.iabGroups.specialFeatures[o] = n
                }
            }
        }),
        a.forEach(function(e) {
            s[e.Parent] && e.ShowInPopup && (e.FirstPartyCookies.length || e.Hosts.length || e.GeneralVendorsIds && e.GeneralVendorsIds.length || -1 < bt.indexOf(e.Type)) && s[e.Parent].SubGroups.push(e)
        });
        var t = [];
        return Object.keys(s).forEach(function(e) {
            i.isValidConsentNoticeGroup(s[e], r.IsIabEnabled) && (s[e].SubGroups.sort(function(e, t) {
                return e.Order - t.Order
            }),
            t.push(s[e]))
        }),
        this.initGrpVar(t),
        t.sort(function(e, t) {
            return e.Order - t.Order
        })
    }
    ,
    Gt.prototype.initGrpVar = function(e) {
        var o = this
          , n = !0
          , r = !0;
        e.forEach(function(e) {
            y([e], e.SubGroups).forEach(function(e) {
                var t;
                e.Type !== Ct && e.Type !== ft && e.Type !== vt || (o.domainGrps[e.PurposeId.toLowerCase()] = e.CustomGroupId),
                -1 < Pt.indexOf(e.Type) && o.consentableGrps.push(e),
                -1 < St.indexOf(e.Type) && o.consentableIabGrps.push(e),
                -1 === Pt.indexOf(e.Type) && o.iabGrps.push(e),
                o.gpcEnabled && e.IsGpcEnabled && (e.Status = Re),
                (t = o.DNTEnabled && e.IsDntEnabled ? qe : e.Status.toLowerCase()) !== He && t !== Fe && t !== qe || (n = !1),
                t !== Fe && t !== De && (r = !1),
                o.gpcForAGrpEnabled || (o.gpcForAGrpEnabled = e.IsGpcEnabled)
            })
        }),
        this.isOptInMode = n,
        this.isSoftOptInMode = r
    }
    ,
    Gt.prototype.domainDataMapper = function(e) {
        var t = {
            AriaClosePreferences: e.AriaClosePreferences,
            AriaOpenPreferences: e.AriaOpenPreferences,
            AriaPrivacy: e.AriaPrivacy,
            CenterRounded: e.CenterRounded,
            Flat: e.Flat,
            FloatingFlat: e.FloatingFlat,
            FloatingRounded: e.FloatingRounded,
            FloatingRoundedCorner: e.FloatingRoundedCorner,
            FloatingRoundedIcon: e.FloatingRoundedIcon,
            VendorLevelOptOut: e.IsIabEnabled,
            AboutCookiesText: e.AboutCookiesText,
            AboutLink: e.AboutLink,
            AboutText: e.AboutText,
            ActiveText: e.ActiveText,
            AddLinksToCookiepedia: e.AddLinksToCookiepedia,
            AdvancedAnalyticsCategory: e.AdvancedAnalyticsCategory || "",
            AlertAllowCookiesText: e.AlertAllowCookiesText,
            AlertCloseText: e.AlertCloseText,
            AlertLayout: e.AlertLayout,
            AlertMoreInfoText: e.AlertMoreInfoText,
            AlertNoticeText: e.AlertNoticeText,
            AllowAllText: e.PreferenceCenterConfirmText,
            AlwaysActiveText: e.AlwaysActiveText,
            BannerAdditionalDescPlacement: e.BannerAdditionalDescPlacement,
            BannerAdditionalDescription: e.BannerAdditionalDescription,
            BannerCloseButtonText: e.BannerCloseButtonText,
            BannerDPDDescription: e.BannerDPDDescription || [],
            BannerDPDDescriptionFormat: e.BannerDPDDescriptionFormat || "",
            BannerDPDTitle: e.BannerDPDTitle || "",
            BannerFeatureDescription: e.BannerFeatureDescription,
            BannerFeatureTitle: e.BannerFeatureTitle,
            BannerIABPartnersLink: e.BannerIABPartnersLink,
            BannerInformationDescription: e.BannerInformationDescription,
            BannerInformationTitle: e.BannerInformationTitle,
            BannerNonIABVendorListText: e.BannerNonIABVendorListText,
            BannerPosition: e.BannerPosition,
            BannerPurposeDescription: e.BannerPurposeDescription,
            BannerPurposeTitle: e.BannerPurposeTitle,
            BannerRejectAllButtonText: e.BannerRejectAllButtonText,
            BannerRelativeFontSizesToggle: e.BannerRelativeFontSizesToggle,
            BannerSettingsButtonDisplayLink: e.BannerSettingsButtonDisplayLink,
            BannerShowRejectAllButton: e.BannerShowRejectAllButton,
            BannerTitle: e.BannerTitle,
            BCloseButtonType: e.BCloseButtonType,
            BContinueText: e.BContinueText,
            BCookiePolicyLinkScreenReader: e.BCookiePolicyLinkScreenReader,
            BImprintLinkScreenReader: e.BImprintLinkScreenReader,
            BInitialFocus: e.BInitialFocus,
            BInitialFocusLinkAndButton: e.BInitialFocusLinkAndButton,
            BSaveBtnTxt: e.BSaveBtnText,
            BShowImprintLink: e.BShowImprintLink,
            BShowPolicyLink: e.BShowPolicyLink,
            BShowSaveBtn: e.BShowSaveBtn,
            CategoriesText: e.CategoriesText || "Categories",
            cctId: e.cctId,
            ChoicesBanner: e.ChoicesBanner,
            CloseShouldAcceptAllCookies: e.CloseShouldAcceptAllCookies,
            CloseText: e.CloseText,
            ConfirmText: e.ConfirmText,
            ConsentModel: {
                Name: e.ConsentModel
            },
            CookieListDescription: e.CookieListDescription,
            CookieListTitle: e.CookieListTitle,
            CookieSettingButtonText: e.CookieSettingButtonText,
            CookiesText: e.CookiesText || "Cookies",
            CookiesUsedText: e.CookiesUsedText,
            CustomJs: e.CustomJs,
            firstPartyTxt: e.CookieFirstPartyText,
            FooterDescriptionText: e.FooterDescriptionText,
            ForceConsent: e.ForceConsent,
            GeneralVendors: e.GeneralVendors,
            GeneralVendorsEnabled: e.PCenterUseGeneralVendorsToggle,
            GenVenOptOut: e.PCenterAllowVendorOptout,
            GlobalRestrictionEnabled: e.GlobalRestrictionEnabled,
            GlobalRestrictions: e.GlobalRestrictions,
            GoogleConsent: {
                GCAdStorage: e.GCAdStorage,
                GCAnalyticsStorage: e.GCAnalyticsStorage,
                GCEnable: e.GCEnable,
                GCFunctionalityStorage: e.GCFunctionalityStorage,
                GCPersonalizationStorage: e.GCPersonalizationStorage,
                GCRedactEnable: e.GCRedactEnable,
                GCSecurityStorage: e.GCSecurityStorage,
                GCWaitTime: e.GCWaitTime
            },
            GroupGenVenListLabel: e.PCenterGeneralVendorThirdPartyCookiesText,
            Groups: this.populateGroups(e.Groups, e),
            HideToolbarCookieList: e.HideToolbarCookieList,
            IabType: e.IabType,
            InactiveText: e.InactiveText,
            IsConsentLoggingEnabled: e.IsConsentLoggingEnabled,
            IsIabEnabled: e.IsIabEnabled,
            IsIabThirdPartyCookieEnabled: e.IsIabThirdPartyCookieEnabled,
            IsLifespanEnabled: e.IsLifespanEnabled,
            Language: e.Language,
            LastReconsentDate: e.LastReconsentDate,
            LfSpanSecs: e.PCLifeSpanSecs,
            LfSpnWk: e.PCLifeSpanWk,
            LfSpnWks: e.PCLifeSpanWks,
            LfSpnYr: e.PCLifeSpanYr,
            LfSpnYrs: e.PCLifeSpanYrs,
            LifespanDurationText: e.LifespanDurationText,
            LifespanText: e.LifespanText || "Lifespan",
            LifespanTypeText: e.LifespanTypeText || "Session",
            MainInfoText: e.MainInfoText,
            MainText: e.MainText,
            ManagePreferenceText: e.PreferenceCenterManagePreferencesText,
            NewVendorsInactiveEnabled: e.NewVendorsInactiveEnabled,
            NewWinTxt: e.PreferenceCenterMoreInfoScreenReader,
            NextPageAcceptAllCookies: e.NextPageAcceptAllCookies,
            NextPageCloseBanner: e.NextPageCloseBanner,
            NoBanner: e.NoBanner,
            OnClickAcceptAllCookies: e.OnClickAcceptAllCookies,
            OnClickCloseBanner: e.OnClickCloseBanner,
            OverriddenVendors: e.OverriddenVendors,
            OverridenGoogleVendors: e.OverridenGoogleVendors,
            PCAccordionStyle: W.Caret,
            PCActiveText: e.PCActiveText,
            PCCloseButtonType: e.PCCloseButtonType,
            PCContinueText: e.PCContinueText,
            PCCookiePolicyLinkScreenReader: e.PCCookiePolicyLinkScreenReader,
            PCCookiePolicyText: e.PCCookiePolicyText,
            PCenterAllowAllConsentText: e.PCenterAllowAllConsentText,
            PCenterApplyFiltersText: e.PCenterApplyFiltersText,
            PCenterBackText: e.PCenterBackText,
            PCenterCancelFiltersText: e.PCenterCancelFiltersText,
            PCenterClearFiltersText: e.PCenterClearFiltersText,
            PCenterConsentText: e.PCenterConsentText || "Consent",
            PCenterCookieListFilterAria: e.PCenterCookieListFilterAria || "Filter",
            PCenterCookieListSearch: e.PCenterCookieListSearch || "Search",
            PCenterCookieSearchAriaLabel: e.PCenterCookieSearchAriaLabel || "Cookie list search",
            PCenterCookiesListText: e.PCenterCookiesListText,
            PCenterEnableAccordion: e.PCenterEnableAccordion,
            PCenterFilterAppliedAria: e.PCenterFilterAppliedAria || "Applied",
            PCenterFilterClearedAria: e.PCenterFilterClearedAria || "Filters Cleared",
            PCenterFilterText: e.PCenterFilterText,
            PCenterGeneralVendorsText: e.PCenterGeneralVendorsText,
            PCenterLegIntColumnHeader: e.PCenterLegIntColumnHeader || "Legitimate Interest",
            PCenterLegitInterestText: e.PCenterLegitInterestText || "Legitimate Interest",
            PCenterRejectAllButtonText: e.PCenterRejectAllButtonText,
            PCenterSelectAllVendorsText: e.PCenterSelectAllVendorsText,
            PCenterShowRejectAllButton: e.PCenterShowRejectAllButton,
            PCenterUserIdDescriptionText: e.PCenterUserIdDescriptionText,
            PCenterUserIdNotYetConsentedText: e.PCenterUserIdNotYetConsentedText,
            PCenterUserIdTimestampTitleText: e.PCenterUserIdTimestampTitleText,
            PCenterUserIdTitleText: e.PCenterUserIdTitleText,
            PCenterVendorListDescText: e.PCenterVendorListDescText,
            PCenterVendorListDisclosure: e.PCenterVendorListDisclosure,
            PCenterVendorListFilterAria: e.PCenterVendorListFilterAria || "Filter",
            PCenterVendorListLifespan: e.PCenterVendorListLifespan,
            PCenterVendorListLifespanDay: e.PCenterVendorListLifespanDay,
            PCenterVendorListLifespanDays: e.PCenterVendorListLifespanDays,
            PCenterVendorListLifespanMonth: e.PCenterVendorListLifespanMonth,
            PCenterVendorListLifespanMonths: e.PCenterVendorListLifespanMonths,
            PCenterVendorListNonCookieUsage: e.PCenterVendorListNonCookieUsage,
            PCenterVendorListSearch: e.PCenterVendorListSearch || "Search",
            PCenterVendorListStorageDomain: e.PCenterVendorListStorageDomain,
            PCenterVendorListStorageIdentifier: e.PCenterVendorListStorageIdentifier,
            PCenterVendorListStoragePurposes: e.PCenterVendorListStoragePurposes,
            PCenterVendorListStorageType: e.PCenterVendorListStorageType,
            PCenterVendorSearchAriaLabel: e.PCenterVendorSearchAriaLabel || "Vendor list search",
            PCenterVendorsListText: e.PCenterVendorsListText,
            PCenterViewPrivacyPolicyText: e.PCenterViewPrivacyPolicyText,
            PCFirstPartyCookieListText: e.PCFirstPartyCookieListText || "First Party Cookies",
            PCGoogleVendorsText: e.PCGoogleVendorsText,
            PCGrpDescLinkPosition: e.PCGrpDescLinkPosition,
            PCGrpDescType: e.PCGrpDescType,
            PCGVenPolicyTxt: e.PCGeneralVendorsPolicyText,
            PCIABVendorsText: e.PCIABVendorsText,
            PCInactiveText: e.PCInactiveText,
            PCLogoAria: e.PCLogoScreenReader,
            PCOpensCookiesDetailsAlert: e.PCOpensCookiesDetailsAlert,
            PCenterVendorListScreenReader: e.PCenterVendorListScreenReader,
            PCOpensVendorDetailsAlert: e.PCOpensVendorDetailsAlert,
            PCShowConsentLabels: !(!e.Tab || !e.PCTemplateUpgrade) && e.PCShowConsentLabels,
            PCShowPersistentCookiesHoverButton: e.PCShowPersistentCookiesHoverButton || !1,
            PCTemplateUpgrade: e.PCTemplateUpgrade,
            PCVendorFullLegalText: e.PCVendorFullLegalText,
            PCViewCookiesText: e.PCViewCookiesText,
            PCLayout: {
                Center: e.Center,
                List: e.List,
                Panel: e.Panel,
                Popup: e.Popup,
                Tab: e.Tab
            },
            PCenterVendorListLinkText: e.PCenterVendorListLinkText,
            PCenterVendorListLinkAriaLabel: e.PCenterVendorListLinkAriaLabel,
            PreferenceCenterPosition: e.PreferenceCenterPosition,
            Publisher: e.publisher,
            PublisherCC: e.PublisherCC,
            ReconsentFrequencyDays: e.ReconsentFrequencyDays,
            ScrollAcceptAllCookies: e.ScrollAcceptAllCookies,
            ScrollCloseBanner: e.ScrollCloseBanner,
            ShowAlertNotice: e.ShowAlertNotice,
            showBannerCloseButton: e.showBannerCloseButton,
            ShowPreferenceCenterCloseButton: e.ShowPreferenceCenterCloseButton,
            ThirdPartyCookieListText: e.ThirdPartyCookieListText,
            thirdPartyTxt: e.CookieThirdPartyText,
            UseGoogleVendors: this.canUseGoogleVendors(e.PCTemplateUpgrade),
            VendorConsentModel: e.VendorConsentModel,
            VendorListText: e.VendorListText,
            Vendors: e.Vendors,
            PCCategoryStyle: e.PCCategoryStyle,
            VendorServiceConfig: {
                PCVSOptOut: e.PCVSOptOut,
                PCVSEnable: e.PCVSEnable,
                PCVSAlwaysActive: e.PCVSAlwaysActive,
                PCVSExpandCategory: e.PCVSExpandCategory,
                PCVSExpandGroup: e.PCVSExpandGroup,
                PCVSCategoryView: e.PCVSCategoryView,
                PCVSNameText: e.PCVSNameText,
                PCVSAllowAllText: e.PCVSAllowAllText,
                PCVSListTitle: e.PCVSListTitle,
                PCVSParentCompanyText: e.PCVSParentCompanyText,
                PCVSAddressText: e.PCVSAddressText,
                PCVSDefaultCategoryText: e.PCVSDefaultCategoryText,
                PCVSDefaultDescriptionText: e.PCVSDefaultDescriptionText,
                PCVSDPOEmailText: e.PCVSDPOEmailText,
                PCVSDPOLinkText: e.PCVSDPOLinkText,
                PCVSPrivacyPolicyLinkText: e.PCVSPrivacyPolicyLinkText,
                PCVSCookiePolicyLinkText: e.PCVSCookiePolicyLinkText,
                PCVSOptOutLinkText: e.PCVSOptOutLinkText,
                PCVSLegalBasisText: e.PCVSLegalBasisText
            }
        };
        e.PCTemplateUpgrade && (e.Center || e.Panel) && e.PCAccordionStyle === W.PlusMinus && (t.PCAccordionStyle = e.PCAccordionStyle),
        t.PCenterEnableAccordion = e.PCAccordionStyle !== W.NoAccordion,
        this.legIntSettings = e.LegIntSettings || {},
        void 0 === this.legIntSettings.PAllowLI && (this.legIntSettings.PAllowLI = !0),
        It.moduleInitializer.MobileSDK || (this.pagePushedDown = e.BannerPushesDownPage),
        Nt = r(r({}, Nt), t)
    }
    ,
    Gt.prototype.commonDataMapper = function(e) {
        var t = {
            iabThirdPartyConsentUrl: e.IabThirdPartyCookieUrl,
            optanonHideAcceptButton: e.OptanonHideAcceptButton,
            optanonHideCookieSettingButton: e.OptanonHideCookieSettingButton,
            optanonStyle: e.OptanonStyle,
            optanonStaticContentLocation: e.OptanonStaticContentLocation,
            bannerCustomCSS: e.BannerCustomCSS.replace(/\\n/g, ""),
            pcCustomCSS: e.PCCustomCSS.replace(/\\n/g, ""),
            textColor: e.TextColor,
            buttonColor: e.ButtonColor,
            buttonTextColor: e.ButtonTextColor,
            bannerMPButtonColor: e.BannerMPButtonColor,
            bannerMPButtonTextColor: e.BannerMPButtonTextColor,
            backgroundColor: e.BackgroundColor,
            bannerAccordionBackgroundColor: e.BannerAccordionBackgroundColor,
            BContinueColor: e.BContinueColor,
            PCContinueColor: e.PCContinueColor,
            pcTextColor: e.PcTextColor,
            pcButtonColor: e.PcButtonColor,
            pcButtonTextColor: e.PcButtonTextColor,
            pcAccordionBackgroundColor: e.PcAccordionBackgroundColor,
            pcLinksTextColor: e.PcLinksTextColor,
            bannerLinksTextColor: e.BannerLinksTextColor,
            pcEnableToggles: e.PcEnableToggles,
            pcBackgroundColor: e.PcBackgroundColor,
            pcMenuColor: e.PcMenuColor,
            pcMenuHighLightColor: e.PcMenuHighLightColor,
            legacyBannerLayout: e.LegacyBannerLayout,
            optanonLogo: e.OptanonLogo,
            oneTrustFtrLogo: e.OneTrustFooterLogo,
            optanonCookieDomain: e.OptanonCookieDomain,
            cookiePersistentLogo: e.CookiePersistentLogo,
            optanonGroupIdPerformanceCookies: e.OptanonGroupIdPerformanceCookies,
            optanonGroupIdFunctionalityCookies: e.OptanonGroupIdFunctionalityCookies,
            optanonGroupIdTargetingCookies: e.OptanonGroupIdTargetingCookies,
            optanonGroupIdSocialCookies: e.OptanonGroupIdSocialCookies,
            optanonShowSubGroupCookies: e.ShowSubGroupCookies,
            useRTL: e.UseRTL,
            showBannerCookieSettings: e.ShowBannerCookieSettings,
            showBannerAcceptButton: e.ShowBannerAcceptButton,
            showCookieList: e.ShowCookieList,
            allowHostOptOut: e.AllowHostOptOut,
            CookiesV2NewCookiePolicy: e.CookiesV2NewCookiePolicy,
            cookieListTitleColor: e.CookieListTitleColor,
            cookieListGroupNameColor: e.CookieListGroupNameColor,
            cookieListTableHeaderColor: e.CookieListTableHeaderColor,
            CookieListTableHeaderBackgroundColor: e.CookieListTableHeaderBackgroundColor,
            cookieListPrimaryColor: e.CookieListPrimaryColor,
            cookieListCustomCss: e.CookieListCustomCss,
            pcShowCookieHost: e.PCShowCookieHost,
            pcShowCookieDuration: e.PCShowCookieDuration,
            pcShowCookieType: e.PCShowCookieType,
            pcShowCookieCategory: e.PCShowCookieCategory,
            pcShowCookieDescription: e.PCShowCookieDescription,
            ConsentIntegration: e.ConsentIntegration,
            ConsentPurposesText: e.BConsentPurposesText || "Consent Purposes",
            FeaturesText: e.BFeaturesText || "Features",
            LegitimateInterestPurposesText: e.BLegitimateInterestPurposesText || "Legitimate Interest Purposes",
            ConsentText: e.BConsentText || "Consent",
            LegitInterestText: e.BLegitInterestText || "Legit. Interest",
            pcDialogClose: e.PCDialogClose || "dialog closed",
            pCFooterLogoUrl: e.PCFooterLogoUrl,
            SpecialFeaturesText: e.BSpecialFeaturesText || "Special Features",
            SpecialPurposesText: e.BSpecialPurposesText || "Special Purposes",
            pcCListName: e.PCCListName || "Name",
            pcCListHost: e.PCCListHost || "Host",
            pcCListDuration: e.PCCListDuration || "Duration",
            pcCListType: e.PCCListType || "Type",
            pcCListCategory: e.PCCListCategory || "Category",
            pcCListDescription: e.PCCListDescription || "Description",
            IabLegalTextUrl: e.IabLegalTextUrl,
            pcLegIntButtonColor: e.PcLegIntButtonColor,
            pcLegIntButtonTextColor: e.PcLegIntButtonTextColor,
            PCenterExpandToViewText: e.PCenterExpandToViewText,
            BCategoryContainerColor: e.BCategoryContainerColor,
            BCategoryStyleColor: e.BCategoryStyleColor,
            BLineBreakColor: e.BLineBreakColor,
            BSaveBtnColor: e.BSaveBtnColor,
            BCategoryStyle: e.BCategoryStyle,
            BAnimation: e.BAnimation,
            BFocusBorderColor: e.BFocusBorderColor,
            PCFocusBorderColor: e.PCFocusBorderColor
        };
        Nt = r(r({}, Nt), t)
    }
    ,
    Gt.prototype.setPublicDomainData = function(r) {
        this.pubDomainData = {
            AboutCookiesText: r.AboutCookiesText,
            AboutLink: r.AboutLink,
            AboutText: r.AboutText,
            ActiveText: r.ActiveText,
            AddLinksToCookiepedia: r.AddLinksToCookiepedia,
            AlertAllowCookiesText: r.AlertAllowCookiesText,
            AlertCloseText: r.AlertCloseText,
            AlertLayout: r.AlertLayout,
            AlertMoreInfoText: r.AlertMoreInfoText,
            AlertNoticeText: r.AlertNoticeText,
            AllowAllText: r.PreferenceCenterConfirmText,
            AlwaysActiveText: r.AlwaysActiveText,
            BAnimation: r.BAnimation,
            BannerCloseButtonText: r.BannerCloseButtonText,
            BannerDPDDescription: r.BannerDPDDescription || [],
            BannerDPDDescriptionFormat: r.BannerDPDDescriptionFormat || "",
            BannerDPDTitle: r.BannerDPDTitle || "",
            BannerFeatureDescription: r.BannerFeatureDescription,
            BannerFeatureTitle: r.BannerFeatureTitle,
            BannerIABPartnersLink: r.BannerIABPartnersLink,
            BannerInformationDescription: r.BannerInformationDescription,
            BannerInformationTitle: r.BannerInformationTitle,
            BannerPosition: r.BannerPosition,
            BannerPurposeDescription: r.BannerPurposeDescription,
            BannerPurposeTitle: r.BannerPurposeTitle,
            BannerRejectAllButtonText: r.BannerRejectAllButtonText,
            BannerRelativeFontSizesToggle: r.BannerRelativeFontSizesToggle,
            BannerSettingsButtonDisplayLink: r.BannerSettingsButtonDisplayLink,
            BannerShowRejectAllButton: r.BannerShowRejectAllButton,
            BannerTitle: r.BannerTitle,
            BCategoryContainerColor: r.BCategoryContainerColor,
            BCategoryStyle: r.BCategoryStyle,
            BCategoryStyleColor: r.BCategoryStyleColor,
            BCloseButtonType: r.BCloseButtonType,
            BContinueText: r.BContinueText,
            BInitialFocus: r.BInitialFocus,
            BInitialFocusLinkAndButton: r.BInitialFocusLinkAndButton,
            BLineBreakColor: r.BLineBreakColor,
            BSaveBtnColor: r.BSaveBtnColor,
            BSaveBtnTxt: r.BSaveBtnText,
            BShowSaveBtn: r.BShowSaveBtn,
            CategoriesText: r.CategoriesText,
            cctId: r.cctId,
            ChoicesBanner: r.ChoicesBanner,
            CloseShouldAcceptAllCookies: r.CloseShouldAcceptAllCookies,
            CloseText: r.CloseText,
            ConfirmText: r.ConfirmText,
            ConsentIntegrationData: null,
            ConsentModel: {
                Name: r.ConsentModel
            },
            CookieListDescription: r.CookieListDescription,
            CookieListTitle: r.CookieListTitle,
            CookieSettingButtonText: r.CookieSettingButtonText,
            CookiesText: r.CookiesText,
            CookiesUsedText: r.CookiesUsedText,
            CustomJs: r.CustomJs,
            Domain: It.moduleInitializer.Domain,
            FooterDescriptionText: r.FooterDescriptionText,
            ForceConsent: r.ForceConsent,
            GeneralVendors: r.GeneralVendors,
            GoogleConsent: {
                GCAdStorage: r.GCAdStorage,
                GCAnalyticsStorage: r.GCAnalyticsStorage,
                GCEnable: r.GCEnable,
                GCFunctionalityStorage: r.GCFunctionalityStorage,
                GCPersonalizationStorage: r.GCPersonalizationStorage,
                GCRedactEnable: r.GCRedactEnable,
                GCSecurityStorage: r.GCSecurityStorage,
                GCWaitTime: r.GCWaitTime
            },
            Groups: null,
            HideToolbarCookieList: r.HideToolbarCookieList,
            IabType: r.IabType,
            InactiveText: r.InactiveText,
            IsBannerLoaded: !1,
            IsConsentLoggingEnabled: r.IsConsentLoggingEnabled,
            IsIABEnabled: r.IsIabEnabled,
            IsIabThirdPartyCookieEnabled: r.IsIabThirdPartyCookieEnabled,
            IsLifespanEnabled: r.IsLifespanEnabled,
            Language: r.Language,
            LastReconsentDate: r.LastReconsentDate,
            LifespanDurationText: r.LifespanDurationText,
            LifespanText: r.LifespanText,
            LifespanTypeText: r.LifespanTypeText,
            MainInfoText: r.MainInfoText,
            MainText: r.MainText,
            ManagePreferenceText: r.PreferenceCenterManagePreferencesText,
            NextPageAcceptAllCookies: r.NextPageAcceptAllCookies,
            NextPageCloseBanner: r.NextPageCloseBanner,
            NoBanner: r.NoBanner,
            OnClickAcceptAllCookies: r.OnClickAcceptAllCookies,
            OnClickCloseBanner: r.OnClickCloseBanner,
            OverridenGoogleVendors: r.OverridenGoogleVendors,
            PCAccordionStyle: W.Caret,
            PCCloseButtonType: r.PCCloseButtonType,
            PCContinueText: r.PCContinueText,
            PCenterAllowAllConsentText: r.PCenterAllowAllConsentText,
            PCenterApplyFiltersText: r.PCenterApplyFiltersText,
            PCenterBackText: r.PCenterBackText,
            PCenterCancelFiltersText: r.PCenterCancelFiltersText,
            PCenterClearFiltersText: r.PCenterClearFiltersText,
            PCenterCookieSearchAriaLabel: r.PCenterCookieSearchAriaLabel || "Cookie list search",
            PCenterCookiesListText: r.PCenterCookiesListText,
            PCenterEnableAccordion: r.PCenterEnableAccordion,
            PCenterExpandToViewText: r.PCenterExpandToViewText,
            PCenterFilterAppliedAria: r.PCenterFilterAppliedAria || "Applied",
            PCenterFilterClearedAria: r.PCenterFilterClearedAria || "Filters Cleared",
            PCenterFilterText: r.PCenterFilterText,
            PCenterRejectAllButtonText: r.PCenterRejectAllButtonText,
            PCenterSelectAllVendorsText: r.PCenterSelectAllVendorsText,
            PCenterShowRejectAllButton: r.PCenterShowRejectAllButton,
            PCenterUserIdDescriptionText: r.PCenterUserIdDescriptionText,
            PCenterUserIdNotYetConsentedText: r.PCenterUserIdNotYetConsentedText,
            PCenterUserIdTimestampTitleText: r.PCenterUserIdTimestampTitleText,
            PCenterUserIdTitleText: r.PCenterUserIdTitleText,
            PCenterVendorListDescText: r.PCenterVendorListDescText,
            PCenterVendorSearchAriaLabel: r.PCenterVendorSearchAriaLabel || "Vendor list search",
            PCenterVendorsListText: r.PCenterVendorsListText,
            PCenterViewPrivacyPolicyText: r.PCenterViewPrivacyPolicyText,
            PCFirstPartyCookieListText: r.PCFirstPartyCookieListText,
            PCGoogleVendorsText: r.PCGoogleVendorsText,
            PCGrpDescLinkPosition: r.PCGrpDescLinkPosition,
            PCGrpDescType: r.PCGrpDescType,
            PCIABVendorsText: r.PCIABVendorsText,
            PCLogoAria: r.PCLogoScreenReader,
            PCOpensCookiesDetailsAlert: r.PCOpensCookiesDetailsAlert,
            PCenterVendorListScreenReader: r.PCenterVendorListScreenReader,
            PCOpensVendorDetailsAlert: r.PCOpensVendorDetailsAlert,
            PCShowPersistentCookiesHoverButton: r.PCShowPersistentCookiesHoverButton,
            PCTemplateUpgrade: r.PCTemplateUpgrade,
            PCVendorFullLegalText: r.PCVendorFullLegalText,
            PCViewCookiesText: r.PCViewCookiesText,
            PCLayout: {
                Center: r.Center,
                List: r.List,
                Panel: r.Panel,
                Popup: r.Popup,
                Tab: r.Tab
            },
            PCenterVendorListLinkText: r.PCenterVendorListLinkText,
            PCenterVendorListLinkAriaLabel: r.PCenterVendorListLinkAriaLabel,
            PreferenceCenterPosition: r.PreferenceCenterPosition,
            ScrollAcceptAllCookies: r.ScrollAcceptAllCookies,
            ScrollCloseBanner: r.ScrollCloseBanner,
            ShowAlertNotice: r.ShowAlertNotice,
            showBannerCloseButton: r.showBannerCloseButton,
            ShowPreferenceCenterCloseButton: r.ShowPreferenceCenterCloseButton,
            ThirdPartyCookieListText: r.ThirdPartyCookieListText,
            UseGoogleVendors: this.canUseGoogleVendors(r.PCTemplateUpgrade),
            VendorConsentModel: r.VendorConsentModel,
            VendorLevelOptOut: r.IsIabEnabled,
            VendorListText: r.VendorListText
        },
        r.PCTemplateUpgrade && (r.Center || r.Panel) && r.PCAccordionStyle !== W.NoAccordion && (this.pubDomainData.PCAccordionStyle = r.PCAccordionStyle),
        this.pubDomainData.PCenterEnableAccordion = r.PCAccordionStyle !== W.NoAccordion;
        var i = [];
        r.Groups.forEach(function(e) {
            var t, o;
            if (r.IsIabEnabled || !e.IsIabPurpose) {
                e.Cookies = JSON.parse(JSON.stringify(e.FirstPartyCookies));
                var n = null === (o = e.Hosts) || void 0 === o ? void 0 : o.reduce(function(e, t) {
                    return e.concat(JSON.parse(JSON.stringify(t.Cookies)))
                }, []);
                (t = e.Cookies).push.apply(t, n),
                i.push(e)
            }
        }),
        this.pubDomainData.Groups = i
    }
    ,
    Gt.prototype.setBannerScriptElement = function(e) {
        this.bannerScriptElement = e,
        this.setDomainElementAttributes()
    }
    ,
    Gt.prototype.setDomainElementAttributes = function() {
        this.bannerScriptElement && (this.bannerScriptElement.hasAttribute("data-document-language") && this.setUseDocumentLanguage("true" === this.bannerScriptElement.getAttribute("data-document-language")),
        this.bannerScriptElement.hasAttribute("data-ignore-ga") && (this.ignoreGoogleAnlyticsCall = "true" === this.bannerScriptElement.getAttribute("data-ignore-ga")),
        this.bannerScriptElement.hasAttribute("data-ignore-html") && (this.ignoreInjectingHtmlCss = "true" === this.bannerScriptElement.getAttribute("data-ignore-html")))
    }
    ,
    Gt.prototype.setUseDocumentLanguage = function(e) {
        this.useDocumentLanguage = e
    }
    ,
    Gt.prototype.setPcName = function() {
        var e = Nt.PCLayout;
        e.Center ? this.pcName = ot : e.Panel ? this.pcName = rt : e.Popup ? this.pcName = it : e.List ? this.pcName = nt : e.Tab && (this.pcName = st)
    }
    ,
    Gt.prototype.setBannerName = function() {
        Nt.Flat ? this.bannerName = Ye : Nt.FloatingRoundedCorner ? this.bannerName = Xe : Nt.FloatingFlat ? this.bannerName = Qe : Nt.FloatingRounded ? this.bannerName = Ze : Nt.FloatingRoundedIcon ? this.bannerName = $e : Nt.CenterRounded ? this.bannerName = Je : Nt.ChoicesBanner ? this.bannerName = et : Nt.NoBanner && (this.bannerName = tt)
    }
    ,
    Gt.prototype.populateGPCSignal = function() {
        var e = Vt.readCookieParam(Ee.OPTANON_CONSENT, Be)
          , t = this.gpcForAGrpEnabled && this.gpcEnabled ? "1" : "0";
        this.gpcValueChanged = e ? e != t : this.gpcForAGrpEnabled,
        this.gpcForAGrpEnabled && Vt.writeCookieParam(Ee.OPTANON_CONSENT, Be, t)
    }
    ,
    Gt.prototype.initGCM = function() {
        var o = [];
        Object.keys(this.rule.States).forEach(function(t) {
            Ot.rule.States[t].forEach(function(e) {
                o.push((t + "-" + e).toUpperCase())
            })
        });
        var e = Ot.rule.Countries.map(function(e) {
            return e.toUpperCase()
        });
        Ot.gcmCountries = e.concat(o)
    }
    ,
    Gt);
    function Gt() {
        var t = this;
        this.DNTEnabled = "yes" === navigator.doNotTrack || "1" === navigator.doNotTrack,
        this.gpcEnabled = !1,
        this.gpcForAGrpEnabled = !1,
        this.pagePushedDown = !1,
        this.iabGroups = {
            purposes: {},
            legIntPurposes: {},
            specialPurposes: {},
            features: {},
            specialFeatures: {}
        },
        this.iabType = null,
        this.grpContainLegalOptOut = !1,
        this.purposeOneTreatment = !1,
        this.ignoreInjectingHtmlCss = !1,
        this.ignoreGoogleAnlyticsCall = !1,
        this.mobileOnlineURL = [],
        this.iabGrpIdMap = {},
        this.iabGrps = [],
        this.consentableGrps = [],
        this.consentableIabGrps = [],
        this.domainGrps = {},
        this.thirdPartyiFrameLoaded = !1,
        this.thirdPartyiFrameResolve = null,
        this.thirdPartyiFramePromise = new Promise(function(e) {
            t.thirdPartyiFrameResolve = e
        }
        ),
        this.isOptInMode = !1,
        this.isSoftOptInMode = !1,
        this.gpcValueChanged = !1,
        this.conditionalLogicEnabled = !1,
        this.allConditionsFailed = !1,
        this.canUseConditionalLogic = !1,
        this.gtmUpdatedinStub = !1,
        this.gcmDevIdSet = !1,
        this.purposeOneGrpId = "IABV2_1"
    }
    var Ot, Nt = {};
    function Dt() {
        this.otSDKVersion = "6.35.0",
        this.isAMP = !1,
        this.ampData = {},
        this.otCookieData = window.OneTrust && window.OneTrust.otCookieData || [],
        this.syncRequired = !1,
        this.isIabSynced = !1,
        this.isGacSynced = !1,
        this.grpsSynced = [],
        this.syncedValidGrp = !1,
        this.groupsConsent = [],
        this.initialGroupsConsent = [],
        this.hostsConsent = [],
        this.initialHostConsent = [],
        this.genVendorsConsent = {},
        this.vsConsent = new Map,
        this.initialGenVendorsConsent = {},
        this.vendors = {
            list: [],
            searchParam: "",
            vendorTemplate: null,
            selectedVendors: [],
            selectedPurpose: [],
            selectedLegInt: [],
            selectedLegIntVendors: [],
            selectedSpecialFeatures: []
        },
        this.initialVendors = {
            list: [],
            searchParam: "",
            vendorTemplate: null,
            selectedVendors: [],
            selectedPurpose: [],
            selectedLegInt: [],
            selectedLegIntVendors: [],
            selectedSpecialFeatures: []
        },
        this.oneTrustIABConsent = {
            purpose: [],
            legimateInterest: [],
            features: [],
            specialFeatures: [],
            specialPurposes: [],
            vendors: [],
            legIntVendors: [],
            vendorList: null,
            IABCookieValue: ""
        },
        this.initialOneTrustIABConsent = {
            purpose: [],
            legimateInterest: [],
            features: [],
            specialFeatures: [],
            specialPurposes: [],
            vendors: [],
            legIntVendors: [],
            vendorList: null,
            IABCookieValue: ""
        },
        this.addtlVendors = {
            vendorConsent: [],
            vendorSelected: {}
        },
        this.initialAddtlVendors = {
            vendorConsent: [],
            vendorSelected: {}
        },
        this.addtlConsentVersion = "1~",
        this.initialAddtlVendorsList = {},
        this.isAddtlConsent = !1,
        this.currentGlobalFilteredList = [],
        this.filterByIABCategories = [],
        this.filterByCategories = [],
        this.hosts = {
            hostTemplate: null,
            hostCookieTemplate: null
        },
        this.generalVendors = {
            gvTemplate: null,
            gvCookieTemplate: null
        },
        this.oneTrustAlwaysActiveHosts = [],
        this.alwaysActiveGenVendors = [],
        this.softOptInGenVendors = [],
        this.optInGenVendors = [],
        this.optanonHostList = [],
        this.srcExecGrps = [],
        this.htmlExecGrps = [],
        this.srcExecGrpsTemp = [],
        this.htmlExecGrpsTemp = [],
        this.isPCVisible = !1,
        this.dataGroupState = [],
        this.userLocation = {
            country: "",
            state: ""
        },
        this.vendorsSetting = {},
        this.dsParams = {},
        this.isV2Stub = !1,
        this.fireOnetrustGrp = !1,
        this.showVendorService = !1,
        this.showGeneralVendors = !1,
        this.genVenOptOutEnabled = !1,
        this.vsIsActiveAndOptOut = !1,
        this.bAsset = {},
        this.pcAsset = {},
        this.csBtnAsset = {},
        this.cStyles = {},
        this.vendorDomInit = !1,
        this.genVendorDomInit = !1,
        this.syncNtfyContent = {},
        this.ntfyRequired = !1,
        this.skipAddingHTML = !1,
        this.bnrAnimationInProg = !1,
        this.isPreview = !1,
        this.geoFromUrl = "",
        this.hideBanner = !1,
        this.setAttributePolyfillIsActive = !1,
        this.storageBaseURL = "",
        this.isKeyboardUser = !1
    }
    var Ht = new (Dt.prototype.getVendorsInDomain = function() {
        var e, t;
        if (!Ht._vendorsInDomain) {
            for (var o = new Map, n = 0, r = null != (e = Nt.Groups) ? e : []; n < r.length; n++)
                for (var i = r[n], s = 0, a = null != (t = i.VendorServices) ? t : []; s < a.length; s++) {
                    var l = a[s]
                      , c = Object.assign({}, i);
                    delete c.VendorServices,
                    l.groupRef = c,
                    o.set(l.CustomVendorServiceId, l)
                }
            Ht._vendorsInDomain = o
        }
        return Ht._vendorsInDomain
    }
    ,
    Dt.prototype.clearVendorsInDomain = function() {
        Ht._vendorsInDomain = null
    }
    ,
    Dt)
      , Ft = (Rt.insertAfter = function(e, t) {
        t.parentNode.insertBefore(e, t.nextSibling)
    }
    ,
    Rt.insertBefore = function(e, t) {
        t.parentNode.insertBefore(e, t)
    }
    ,
    Rt.inArray = function(e, t) {
        return t.indexOf(e)
    }
    ,
    Rt.ajax = function(e) {
        var t, o, n, r, i, s, a = null, l = new XMLHttpRequest;
        t = e.type,
        o = e.url,
        e.dataType,
        n = e.contentType,
        r = e.data,
        i = e.success,
        a = e.error,
        s = e.sync,
        l.open(t, o, !s),
        l.setRequestHeader("Content-Type", n),
        l.onload = function() {
            if (200 <= this.status && this.status < 400) {
                var e = JSON.parse(this.responseText);
                i(e)
            } else
                a({
                    message: "Error Loading Data",
                    statusCode: this.status
                })
        }
        ,
        l.onerror = function(e) {
            a(e)
        }
        ,
        "post" === t.toLowerCase() || "put" === t.toLowerCase() ? l.send(r) : l.send()
    }
    ,
    Rt.prevNextHelper = function(o, e, n) {
        var r = [];
        function i(e, t, o) {
            t[e] && o ? o.includes(".") ? (t[e].classList[0] || t[e].classList.value && t[e].classList.value.includes(o.split(".")[1])) && r.push(t[e]) : o.includes("#") ? t[e].id === o.split("#")[1] && r.push(t[e]) : t[e].tagName === document.createElement(o.trim()).tagName && r.push(t[e]) : t[e] && r.push(t[e])
        }
        return "string" == typeof e ? Array.prototype.forEach.call(document.querySelectorAll(e), function(e, t) {
            i(o, e, n)
        }) : i(o, e, n),
        r
    }
    ,
    Rt.browser = function() {
        var e, t, o;
        return navigator.sayswho = (t = navigator.userAgent,
        o = t.match(/(opera|chrome|safari|firefox|msie|trident(?=\/))\/?\s*(\d+)/i) || [],
        /trident/i.test(o[1]) ? "IE " + ((e = /\brv[ :]+(\d+)/g.exec(t) || [])[1] || "") : "Chrome" === o[1] && null != (e = t.match(/\b(OPR|Edge)\/(\d+)/)) ? e.slice(1).join(" ").replace("OPR", "Opera") : (o = o[2] ? [o[1], o[2]] : [navigator.appName, navigator.appVersion, "-?"],
        null != (e = t.match(/version\/(\d+)/i)) && o.splice(1, 1, e[1]),
        o.join(" "))),
        {
            version: parseInt(navigator.sayswho.split(" ")[1]),
            type: navigator.sayswho.split(" ")[0],
            userAgent: navigator.userAgent
        }
    }
    ,
    Rt.isNodeList = function(e) {
        var t = Object.prototype.toString.call(e);
        return "[object NodeList]" === t || "[object Array]" === t
    }
    ,
    Rt.prototype.fadeOut = function(e) {
        var t = this;
        if (void 0 === e && (e = 60),
        1 <= this.el.length)
            for (var o = 0; o < this.el.length; o++) {
                var n = "\n                    visibility: hidden;\n                    opacity: 0;\n                    transition: visibility 0s " + e + "ms, opacity " + e + "ms linear;\n                ";
                Lt(this.el[o], n, !0)
            }
        var r = setInterval(function() {
            if (1 <= t.el.length)
                for (var e = 0; e < t.el.length; e++)
                    t.el[e].style.opacity <= 0 && (Lt(t.el[e], "display: none;", !0),
                    clearInterval(r),
                    "optanon-popup-bg" === t.el[e].id && t.el[e].removeAttribute("style"))
        }, e);
        return this
    }
    ,
    Rt.prototype.hide = function() {
        if (1 <= this.el.length)
            for (var e = 0; e < this.el.length; e++)
                Lt(this.el[e], "display: none;", !0);
        else
            Rt.isNodeList(this.el) || Lt(this.el, "display: none;", !0);
        return this
    }
    ,
    Rt.prototype.show = function(e) {
        if (void 0 === e && (e = "block"),
        1 <= this.el.length)
            for (var t = 0; t < this.el.length; t++)
                Lt(this.el[t], "display: " + e + ";", !0);
        else
            Rt.isNodeList(this.el) || Lt(this.el, "display: " + e + ";", !0);
        return this
    }
    ,
    Rt.prototype.remove = function() {
        if (1 <= this.el.length)
            for (var e = 0; e < this.el.length; e++)
                this.el[e].parentNode.removeChild(this.el[e]);
        else
            this.el.parentNode.removeChild(this.el);
        return this
    }
    ,
    Rt.prototype.css = function(e) {
        if (e)
            if (1 <= this.el.length) {
                if (!e.includes(":"))
                    return this.el[0].style[e];
                for (var t = 0; t < this.el.length; t++)
                    Lt(this.el[t], e)
            } else {
                if (!e.includes(":"))
                    return this.el.style[e];
                Lt(this.el, e)
            }
        return this
    }
    ,
    Rt.prototype.removeClass = function(e) {
        if (1 <= this.el.length)
            for (var t = 0; t < this.el.length; t++)
                this.el[t].classList ? this.el[t].classList.remove(e) : this.el[t].className = this.el[t].className.replace(new RegExp("(^|\\b)" + e.split(" ").join("|") + "(\\b|$)","gi"), " ");
        else
            this.el.classList ? this.el.classList.remove(e) : this.el.className = this.el.className.replace(new RegExp("(^|\\b)" + e.split(" ").join("|") + "(\\b|$)","gi"), " ");
        return this
    }
    ,
    Rt.prototype.addClass = function(e) {
        if (1 <= this.el.length)
            for (var t = 0; t < this.el.length; t++)
                this.el[t].classList ? this.el[t].classList.add(e) : this.el[t].className += " " + e;
        else
            this.el.classList ? this.el.classList.add(e) : this.el.className += " " + e;
        return this
    }
    ,
    Rt.prototype.on = function(r, i, s) {
        var e = this;
        if ("string" != typeof i)
            if (this.el && "HTML" === this.el.nodeName && "load" === r || "resize" === r || "scroll" === r)
                switch (r) {
                case "load":
                    window.onload = i;
                    break;
                case "resize":
                    window.onresize = i;
                    break;
                case "scroll":
                    window.onscroll = i
                }
            else if (this.el && 1 <= this.el.length)
                for (var t = 0; t < this.el.length; t++)
                    this.el[t].addEventListener(r, i);
            else
                this.el && this.el instanceof Element && this.el.addEventListener(r, i);
        else if (this.el && "HTML" === this.el.nodeName && "load" === r || "resize" === r || "scroll" === r)
            switch (r) {
            case "load":
                window.onload = s;
                break;
            case "resize":
                window.onresize = s;
                break;
            case "scroll":
                window.onscroll = s
            }
        else {
            var a = function(o) {
                var n = o.target;
                e.el.eventExecuted = !0,
                Array.prototype.forEach.call(document.querySelectorAll(i), function(e, t) {
                    Ut["" + r + i] && delete Ut["" + r + i],
                    e.addEventListener(r, s),
                    e === n && s && s.call(e, o)
                }),
                e.el && e.el[0] ? e.el[0].removeEventListener(r, a) : e.el && e.el instanceof Element && e.el.removeEventListener(r, a)
            };
            if (this.el && 1 <= this.el.length)
                for (t = 0; t < this.el.length; t++)
                    this.el[t].eventExecuted = !1,
                    this.el[t].eventExecuted || this.el[t].addEventListener(r, a);
            else
                this.el && (this.el.eventExecuted = !1,
                !this.el.eventExecuted && this.el instanceof Element && (Ut["" + r + i] || (Ut["" + r + i] = !0,
                this.el.addEventListener(r, a))))
        }
        return this
    }
    ,
    Rt.prototype.off = function(e, t) {
        if (1 <= this.el.length)
            for (var o = 0; o < this.el.length; o++)
                this.el[o].removeEventListener(e, t);
        else
            this.el.removeEventListener(e, t);
        return this
    }
    ,
    Rt.prototype.one = function(t, o) {
        var n = this;
        if (1 <= this.el.length)
            for (var e = 0; e < this.el.length; e++)
                this.el[e].addEventListener(t, function(e) {
                    e.stopPropagation(),
                    e.currentTarget.dataset.triggered || (o(),
                    e.currentTarget.dataset.triggered = !0)
                });
        else {
            var r = function(e) {
                e.stopPropagation(),
                o(),
                n.off(t, r)
            };
            this.el.addEventListener(t, r)
        }
        return this
    }
    ,
    Rt.prototype.trigger = function(e) {
        var t = new CustomEvent(e,{
            customEvent: "yes"
        });
        return this.el.dispatchEvent(t),
        this
    }
    ,
    Rt.prototype.focus = function() {
        return 1 <= this.el.length ? this.el[0].focus() : this.el.focus(),
        this
    }
    ,
    Rt.prototype.attr = function(e, t) {
        return this.el && 1 <= this.el.length ? t ? ("class" === e ? this.addClass(t) : this.el[0].setAttribute(e, t),
        this) : this.el[0].getAttribute(e) : t && this.el ? ("class" === e ? this.addClass(t) : this.el.setAttribute(e, t),
        this) : this.el && this.el.getAttribute(e)
    }
    ,
    Rt.prototype.html = function(e) {
        if (null == e)
            return 1 <= this.el.length ? this.el[0].innerHTML : this.el.innerHTML;
        if (1 <= this.el.length)
            for (var t = 0; t < this.el.length; t++)
                this.el[t].innerHTML = e;
        else
            this.el.innerHTML = e;
        return this
    }
    ,
    Rt.prototype.append = function(o) {
        if ("string" != typeof o || o.includes("<") || o.includes(">"))
            if (Array.isArray(o)) {
                var n = this;
                Array.prototype.forEach.call(o, function(e, t) {
                    document.querySelector(n.selector).appendChild(new Rt(e,"ce").el)
                })
            } else if ("string" == typeof o || Array.isArray(o))
                if ("string" == typeof this.selector)
                    document.querySelector(this.selector).appendChild(new Rt(o,"ce").el);
                else if (this.useEl) {
                    var r = document.createDocumentFragment()
                      , i = !(!o.includes("<th") && !o.includes("<td"));
                    if (i) {
                        var e = o.split(" ")[0].split("<")[1];
                        r.appendChild(document.createElement(e)),
                        r.firstChild.innerHTML = o
                    }
                    Array.prototype.forEach.call(this.el, function(e, t) {
                        i ? e.appendChild(r.firstChild) : e.appendChild(new Rt(o,"ce").el)
                    })
                } else
                    this.selector.appendChild(new Rt(o,"ce").el);
            else if ("string" == typeof this.selector)
                document.querySelector(this.selector).appendChild(o);
            else if (1 <= o.length)
                for (var t = 0; t < o.length; t++)
                    this.selector.appendChild(o[t]);
            else
                this.selector.appendChild(o);
        else
            this.el.insertAdjacentText("beforeend", o);
        return this
    }
    ,
    Rt.prototype.text = function(o) {
        if (this.el) {
            if (1 <= this.el.length) {
                if (!o)
                    return this.el[0].textContent;
                Array.prototype.forEach.call(this.el, function(e, t) {
                    e.textContent = o
                })
            } else {
                if (!o)
                    return this.el.textContent;
                this.el.textContent = o
            }
            return this
        }
    }
    ,
    Rt.prototype.data = function(o, n) {
        if (this.el.length < 1)
            return this;
        if (!(1 <= this.el.length))
            return r(this.el, n);
        function r(e, t) {
            if (!t)
                return JSON.parse(e.getAttribute("data-" + o));
            "object" == typeof t ? e.setAttribute("data-" + o, JSON.stringify(t)) : e.setAttribute("data-" + o, t)
        }
        return Array.prototype.forEach.call(this.el, function(e, t) {
            r(e, n)
        }),
        this
    }
    ,
    Rt.prototype.height = function(e) {
        this.el.length && (this.el = this.el[0]);
        for (var t = parseInt(window.getComputedStyle(this.el, null).getPropertyValue("padding-top").split("px")[0]), o = parseInt(window.getComputedStyle(this.el, null).getPropertyValue("padding-bottom").split("px")[0]), n = parseInt(window.getComputedStyle(this.el, null).getPropertyValue("margin-top").split("px")[0]), r = parseInt(window.getComputedStyle(this.el, null).getPropertyValue("margin-bottom").split("px")[0]), i = parseInt(window.getComputedStyle(this.el, null).getPropertyValue("height").split("px")[0]), s = [t, o, n, r], a = 0, l = 0; l < s.length; l++)
            0 < s[l] && (a += s[l]);
        if (!e)
            return this.selector === document ? i : this.el.clientHeight - a;
        var c = e.toString().split(parseInt(e))[1] ? e.toString().split(parseInt(e))[1] : "px"
          , d = "number" == typeof e ? e : parseInt(e.toString().split(c)[0]);
        return (c && "px" === c || "%" === c || "em" === c || "rem" === c) && (0 < d ? Lt(this.el, "height: " + (a + d + c) + ";", !0) : "auto" === e && Lt(this.el, "height: " + e + ";", !0)),
        this
    }
    ,
    Rt.prototype.each = function(e) {
        var t = !1;
        return void 0 === this.el.length && (this.el = [this.el],
        t = !0),
        Array.prototype.forEach.call(this.el, e),
        t && (this.el = this.el[0]),
        this
    }
    ,
    Rt.prototype.is = function(e) {
        return this.el.length ? (this.el[0].matches || this.el[0].matchesSelector || this.el[0].msMatchesSelector || this.el[0].mozMatchesSelector || this.el[0].webkitMatchesSelector || this.el[0].oMatchesSelector).call(this.el[0], e) : (this.el.matches || this.el.matchesSelector || this.el.msMatchesSelector || this.el.mozMatchesSelector || this.el.webkitMatchesSelector || this.el.oMatchesSelector).call(this.el, e)
    }
    ,
    Rt.prototype.filter = function(e) {
        return this.el = Array.prototype.filter.call(document.querySelectorAll(this.selector), e),
        this
    }
    ,
    Rt.prototype.animate = function(s, a) {
        var l, c = this;
        for (var e in this.el = document.querySelector(this.selector),
        s)
            l = e,
            function() {
                var e = parseInt(s[l])
                  , t = s[l].split(parseInt(s[l]))[1] ? s[l].split(parseInt(s[l]))[1] : "px"
                  , o = "\n                      @keyframes slide-" + ("top" === l ? "up" : "down") + "-custom {\n                          0% {\n                              " + ("top" === l ? "top" : "bottom") + ": " + ("top" === l ? c.el.getBoundingClientRect().top : window.innerHeight) + "px !important;\n                          }\n                          100% {\n                              " + ("top" === l ? "top" : "bottom") + ": " + (e + t) + ";\n                          }\n                      }\n                      @-webkit-keyframes slide-" + ("top" === l ? "up" : "down") + "-custom {\n                          0% {\n                              " + ("top" === l ? "top" : "bottom") + ": " + ("top" === l ? c.el.getBoundingClientRect().top : window.innerHeight) + "px !important;\n                          }\n                          100% {\n                              " + ("top" === l ? "top" : "bottom") + ": " + (e + t) + ";\n                          }\n                      }\n                      @-moz-keyframes slide-" + ("top" === l ? "up" : "down") + "-custom {\n                          0% {\n                              " + ("top" === l ? "top" : "bottom") + ": " + ("top" === l ? c.el.getBoundingClientRect().top : window.innerHeight) + "px !important;\n                          }\n                          100% {\n                              " + ("top" === l ? "top" : "bottom") + ": " + (e + t) + ";\n                          }\n                      }\n                      "
                  , n = document.head.querySelector("#onetrust-style");
                if (n ? n.innerHTML += o : ((i = document.createElement("style")).id = "onetrust-legacy-style",
                i.type = "text/css",
                i.innerHTML = o,
                document.head.appendChild(i)),
                Rt.browser().type = Rt.browser().version <= 8) {
                    var r = "top" === l ? "-webkit-animation: slide-up-custom " : "-webkit-animation: slide-down-custom " + a + "ms ease-out forwards;";
                    Lt(c.el, r)
                } else {
                    var i = "\n                        animation-name: " + ("top" === l ? "slide-up-custom" : "slide-down-custom") + ";\n                        animation-duration: " + a + "ms;\n                        animation-fill-mode: forwards;\n                        animation-timing-function: ease-out;\n                    ";
                    Lt(c.el, i, !0)
                }
            }();
        return this
    }
    ,
    Rt.prototype.scrollTop = function() {
        return this.el.scrollTop
    }
    ,
    Rt);
    function Rt(e, t) {
        switch (void 0 === t && (t = ""),
        this.selector = e,
        this.useEl = !1,
        t) {
        case "ce":
            var o = Rt.browser().type.toLowerCase()
              , n = Rt.browser().version;
            if (n < 10 && "safari" === o || "chrome" === o && n <= 44 || n <= 40 && "firefox" === o) {
                var r = document.implementation.createHTMLDocument();
                r.body.innerHTML = e,
                this.el = r.body.children[0]
            } else {
                var i = document.createRange().createContextualFragment(e);
                this.el = i.firstChild
            }
            this.length = 1;
            break;
        case "":
            this.el = e === document || e === window ? document.documentElement : "string" != typeof e ? e : document.querySelectorAll(e),
            this.length = e === document || e === window || "string" != typeof e ? 1 : this.el.length;
            break;
        default:
            this.length = 0
        }
    }
    function qt(e, t) {
        return void 0 === t && (t = ""),
        new Ft(e,t)
    }
    var Mt, Ut = {}, jt = (zt.prototype.addLogoUrls = function() {
        Mt.checkMobileOfflineRequest(Mt.getBannerVersionUrl()) || (Ot.mobileOnlineURL.push(Mt.updateCorrectUrl(Nt.optanonLogo)),
        Ot.mobileOnlineURL.push(Mt.updateCorrectUrl(Nt.oneTrustFtrLogo)))
    }
    ,
    zt.prototype.getCookieLabel = function(e, t, o) {
        if (void 0 === o && (o = !0),
        !e)
            return "";
        var n = e.Name;
        return t && (n = '\n                <a  class="cookie-label"\n                    href="' + (o ? "http://cookiepedia.co.uk/cookies/" : "http://cookiepedia.co.uk/host/") + e.Name + '"\n                    rel="noopener"\n                    target="_blank"\n                >\n                    ' + e.Name + '&nbsp;<span class="ot-scrn-rdr">' + Nt.NewWinTxt + "</span>\n                </a>\n            "),
        n
    }
    ,
    zt.prototype.getBannerSDKAssestsUrl = function() {
        return this.getBannerVersionUrl() + "/assets"
    }
    ,
    zt.prototype.getBannerVersionUrl = function() {
        var e = Ot.bannerScriptElement.getAttribute("src");
        return "" + (-1 !== e.indexOf("/consent/") ? e.split("consent/")[0] + "scripttemplates/" : e.split("otSDKStub")[0]) + It.moduleInitializer.Version
    }
    ,
    zt.prototype.checkMobileOfflineRequest = function(e) {
        return It.moduleInitializer.MobileSDK && new RegExp("^file://","i").test(e)
    }
    ,
    zt.prototype.updateCorrectIABUrl = function(e) {
        var t = It.moduleInitializer.ScriptType;
        if (t === Me || t === je) {
            var o = Bt.getURL(e)
              , n = Ot.bannerScriptElement
              , r = n && n.getAttribute("src") ? Bt.getURL(n.getAttribute("src")) : null;
            r && o && r.hostname !== o.hostname && (e = (e = (r = "" + Ot.bannerDataParentURL) + o.pathname.split("/").pop().replace(/(^\/?)/, "/")).replace(o.hostname, r.hostname))
        }
        return e
    }
    ,
    zt.prototype.updateCorrectUrl = function(e, t) {
        void 0 === t && (t = !1);
        var o = Bt.getURL(e)
          , n = Ot.bannerScriptElement
          , r = n && n.getAttribute("src") ? Bt.getURL(n.getAttribute("src")) : null;
        if (r && o && r.hostname !== o.hostname) {
            var i = It.moduleInitializer.ScriptType;
            if (i === Me || i === je) {
                if (t)
                    return e;
                e = (r = Ot.bannerDataParentURL + "/" + Ot.getRegionRule().Id) + o.pathname.replace(/(^\/?)/, "/")
            } else
                e = e.replace(o.hostname, r.hostname)
        }
        return e
    }
    ,
    zt.prototype.isBundleOrStackActive = function(n, r) {
        void 0 === r && (r = null);
        var i = Ht.oneTrustIABConsent
          , s = !0;
        r = r || Ht.groupsConsent;
        for (var a = 0, e = function() {
            var t = n.SubGroups[a];
            if (t.Type === Ct)
                (-1 < (e = Bt.findIndex(r, function(e) {
                    return e.split(":")[0] === t.CustomGroupId
                })) && "0" === r[e].split(":")[1] || !r.length) && (s = !1);
            else {
                var e, o = t.Type === vt ? i.specialFeatures : i.purpose;
                (-1 < (e = Bt.findIndex(o, function(e) {
                    return e.split(":")[0] === t.IabGrpId
                })) && "false" === o[e].split(":")[1] || !o.length) && (s = !1)
            }
            a++
        }; e(),
        s && a < n.SubGroups.length; )
            ;
        return s
    }
    ,
    zt.prototype.otFetchOfflineFile = function(r) {
        return c(this, void 0, void 0, function() {
            var t, o, n;
            return C(this, function(e) {
                switch (e.label) {
                case 0:
                    return r = r.replace(".json", ".js"),
                    t = r.split("/"),
                    o = t[t.length - 1],
                    n = o.split(".js")[0],
                    [4, new Promise(function(e) {
                        function t() {
                            e(window[n])
                        }
                        Mt.jsonp(r, t, t)
                    }
                    )];
                case 1:
                    return [2, e.sent()]
                }
            })
        })
    }
    ,
    zt.prototype.jsonp = function(e, t, o) {
        Mt.checkMobileOfflineRequest(e) || Ot.mobileOnlineURL.push(e);
        var n = document.createElement("script")
          , r = document.getElementsByTagName("head")[0];
        function i() {
            t()
        }
        n.onreadystatechange = function() {
            "loaded" !== this.readyState && "complete" !== this.readyState || i()
        }
        ,
        n.onload = i,
        n.onerror = function() {
            o()
        }
        ,
        n.type = "text/javascript",
        n.async = !0,
        n.src = e,
        Ht.crossOrigin && n.setAttribute("crossorigin", Ht.crossOrigin),
        r.appendChild(n)
    }
    ,
    zt.prototype.isCookiePolicyPage = function(e) {
        var t = !1
          , o = Bt.removeURLPrefixes(window.location.href)
          , n = qt("<div></div>", "ce").el;
        qt(n).html(e);
        for (var r = n.querySelectorAll("a"), i = 0; i < r.length; i++)
            if (Bt.removeURLPrefixes(r[i].href) === o) {
                t = !0;
                break
            }
        return t
    }
    ,
    zt.prototype.isBannerVisible = function() {
        var e = !1
          , t = document.getElementById("onetrust-banner-sdk");
        return t && t.getAttribute("style") && (e = -1 !== t.getAttribute("style").indexOf("display: none") || -1 !== t.getAttribute("style").indexOf("display:none")),
        e
    }
    ,
    zt.prototype.hideBanner = function() {
        var e = this;
        Ht.bnrAnimationInProg ? setTimeout(function() {
            return e.hideBanner()
        }, 100) : qt("#onetrust-banner-sdk").fadeOut(400)
    }
    ,
    zt.prototype.resetFocusToBody = function() {
        document.activeElement && document.activeElement.blur()
    }
    ,
    zt.prototype.getDuration = function(e) {
        var t = e.Length
          , o = e.DurationType
          , n = "";
        if (!t || 0 === parseInt(t))
            return Nt.LfSpanSecs;
        var r = parseInt(t);
        if (o) {
            var i = 1 < (r = this.round_to_precision(r / o, .5)) ? lt[o] + "s" : lt[o];
            Nt.LifespanDurationText && 1 === o && (i = "LifespanDurationText"),
            n = r + " " + Nt[i]
        } else
            n = this.getDurationText(r);
        return n
    }
    ,
    zt.prototype.isDateCurrent = function(e) {
        var t = e.split("/")
          , o = parseInt(t[1])
          , n = parseInt(t[0])
          , r = parseInt(t[2])
          , i = new Date
          , s = i.getDate()
          , a = i.getFullYear()
          , l = i.getMonth() + 1;
        return a < r || r === a && l < n || r === a && n === l && s <= o
    }
    ,
    zt.prototype.insertFooterLogo = function(e) {
        var t = qt(e).el;
        if (t.length && Nt.oneTrustFtrLogo) {
            var o = Mt.updateCorrectUrl(Nt.oneTrustFtrLogo);
            Mt.checkMobileOfflineRequest(Mt.getBannerVersionUrl()) && (o = Bt.getRelativeURL(o, !0, !0));
            for (var n = 0; n < t.length; n++) {
                var r = t[n].querySelector("img")
                  , i = "Powered by OneTrust " + Nt.NewWinTxt;
                qt(t[n]).attr("href", Nt.pCFooterLogoUrl),
                r.setAttribute("src", o),
                r.setAttribute("title", i),
                qt(t[n]).attr("aria-label", i)
            }
        }
    }
    ,
    zt.prototype.getUTCFormattedDate = function(e) {
        var t = new Date(e);
        return t.getUTCFullYear() + "-" + (t.getUTCMonth() + 1).toString().padStart(2, "0") + "-" + t.getUTCDate().toString().toString().padStart(2, "0") + " " + t.getUTCHours() + ":" + t.getUTCMinutes().toString().toString().padStart(2, "0") + ":" + t.getUTCSeconds().toString().toString().padStart(2, "0")
    }
    ,
    zt.prototype.getDurationText = function(e) {
        return 365 <= e ? (e /= 365,
        (e = this.round_to_precision(e, .5)) + " " + (1 < e ? Nt.LfSpnYrs : Nt.LfSpnYr)) : Nt.LifespanDurationText ? e + " " + Nt.LifespanDurationText : e + " " + (1 < e ? Nt.PCenterVendorListLifespanDays : Nt.PCenterVendorListLifespanDay)
    }
    ,
    zt.prototype.round_to_precision = function(e, t) {
        var o = +e + (void 0 === t ? .5 : t / 2);
        return o - o % (void 0 === t ? 1 : +t)
    }
    ,
    zt.prototype.isOptOutEnabled = function() {
        return Nt.PCTemplateUpgrade ? Ht.genVenOptOutEnabled : Nt.allowHostOptOut
    }
    ,
    zt.prototype.findUserType = function(e) {
        Ht.isKeyboardUser = !(!e || 0 !== e.detail)
    }
    ,
    zt);
    function zt() {}
    var Kt, Wt = {
        P_Content: "#ot-pc-content",
        P_Logo: ".ot-pc-logo",
        P_Title: "#ot-pc-title",
        P_Policy_Txt: "#ot-pc-desc",
        P_Vendor_Title_Elm: "#ot-lst-title",
        P_Vendor_Title: "#ot-lst-title h3",
        P_Manage_Cookies_Txt: "#ot-category-title",
        P_Label_Txt: ".ot-label-txt",
        P_Category_Header: ".ot-cat-header",
        P_Category_Grp: ".ot-cat-grp",
        P_Category_Item: ".ot-cat-item",
        P_Vendor_List: "#ot-pc-lst",
        P_Vendor_Content: "#ot-lst-cnt",
        P_Vendor_Container: "#ot-ven-lst",
        P_Ven_Bx: "ot-ven-box",
        P_Ven_Name: ".ot-ven-name",
        P_Ven_Link: ".ot-ven-link",
        P_Ven_Ctgl: "ot-ven-ctgl",
        P_Ven_Ltgl: "ot-ven-litgl",
        P_Ven_Ltgl_Only: "ot-ven-litgl-only",
        P_Ven_Opts: ".ot-ven-opts",
        P_Triangle: "#ot-anchor",
        P_Fltr_Modal: "#ot-fltr-modal",
        P_Fltr_Options: ".ot-fltr-opts",
        P_Fltr_Option: ".ot-fltr-opt",
        P_Select_Cntr: "#ot-sel-blk",
        P_Host_Cntr: "#ot-host-lst",
        P_Host_Hdr: ".ot-host-hdr",
        P_Host_Desc: ".ot-host-desc",
        P_Li_Hdr: ".ot-pli-hdr",
        P_Li_Title: ".ot-li-title",
        P_Sel_All_Vendor_Consent_Handler: "#select-all-vendor-leg-handler",
        P_Sel_All_Vendor_Leg_Handler: "#select-all-vendor-groups-handler",
        P_Sel_All_Host_Handler: "#select-all-hosts-groups-handler",
        P_Host_Title: ".ot-host-name",
        P_Leg_Select_All: ".ot-sel-all-hdr",
        P_Leg_Header: ".ot-li-hdr",
        P_Acc_Header: ".ot-acc-hdr",
        P_Cnsnt_Header: ".ot-consent-hdr",
        P_Tgl_Cntr: ".ot-tgl-cntr",
        P_CBx_Cntr: ".ot-chkbox",
        P_Sel_All_Host_El: "ot-selall-hostcntr",
        P_Sel_All_Vendor_Consent_El: "ot-selall-vencntr",
        P_Sel_All_Vendor_Leg_El: "ot-selall-licntr",
        P_c_Name: "ot-c-name",
        P_c_Host: "ot-c-host",
        P_c_Duration: "ot-c-duration",
        P_c_Type: "ot-c-type",
        P_c_Category: "ot-c-category",
        P_c_Desc: "ot-c-description",
        P_Host_View_Cookies: ".ot-host-expand",
        P_Host_Opt: ".ot-host-opt",
        P_Host_Info: ".ot-host-info",
        P_Arrw_Cntr: ".ot-arw-cntr",
        P_Acc_Txt: ".ot-acc-txt",
        P_Vendor_CheckBx: "ot-ven-chkbox",
        P_Vendor_LegCheckBx: "ot-ven-leg-chkbox",
        P_Host_UI: "ot-hosts-ui",
        P_Host_Cnt: "ot-host-cnt",
        P_Host_Bx: "ot-host-box",
        P_Ven_Dets: ".ot-ven-dets",
        P_Ven_Disc: ".ot-ven-disc",
        P_Gven_List: "#ot-gn-venlst",
        P_Close_Btn: ".ot-close-icon",
        P_Ven_Lst_Cntr: ".ot-vlst-cntr",
        P_Host_Lst_cntr: ".ot-hlst-cntr",
        P_Sub_Grp_Cntr: ".ot-subgrp-cntr",
        P_Subgrp_Desc: ".ot-subgrp-desc",
        P_Subgp_ul: ".ot-subgrps",
        P_Subgrp_li: ".ot-subgrp",
        P_Subgrp_Tgl_Cntr: ".ot-subgrp-tgl",
        P_Grp_Container: ".ot-grps-cntr",
        P_Privacy_Txt: "#ot-pvcy-txt",
        P_Privacy_Hdr: "#ot-pvcy-hdr",
        P_Active_Menu: "ot-active-menu",
        P_Desc_Container: ".ot-desc-cntr",
        P_Tab_Grp_Hdr: "ot-grp-hdr1",
        P_Search_Cntr: "#ot-search-cntr",
        P_Clr_Fltr_Txt: "#clear-filters-handler",
        P_Acc_Grp_Desc: ".ot-acc-grpdesc",
        P_Acc_Container: ".ot-acc-grpcntr",
        P_Line_Through: "line-through",
        P_Vendor_Search_Input: "#vendor-search-handler"
    }, Jt = {
        P_Grp_Container: ".groups-container",
        P_Content: "#ot-content",
        P_Category_Header: ".category-header",
        P_Desc_Container: ".description-container",
        P_Label_Txt: ".label-text",
        P_Acc_Grp_Desc: ".ot-accordion-group-pc-container",
        P_Leg_Int_Hdr: ".leg-int-header",
        P_Not_Always_Active: "p:not(.ot-always-active)",
        P_Category_Grp: ".category-group",
        P_Category_Item: ".category-item",
        P_Sub_Grp_Cntr: ".cookie-subgroups-container",
        P_Acc_Container: ".ot-accordion-pc-container",
        P_Close_Btn: ".pc-close-button",
        P_Logo: ".pc-logo",
        P_Title: "#pc-title",
        P_Privacy_Txt: "#privacy-text",
        P_Privacy_Hdr: "#pc-privacy-header",
        P_Policy_Txt: "#pc-policy-text",
        P_Manage_Cookies_Txt: "#manage-cookies-text",
        P_Vendor_Title: "#vendors-list-title",
        P_Vendor_Title_Elm: "#vendors-list-title",
        P_Vendor_List: "#vendors-list",
        P_Vendor_Content: "#vendor-list-content",
        P_Vendor_Container: "#vendors-list-container",
        P_Ven_Bx: "vendor-box",
        P_Ven_Name: ".vendor-title",
        P_Ven_Link: ".vendor-privacy-notice",
        P_Ven_Ctgl: "ot-vendor-consent-tgl",
        P_Ven_Ltgl: "ot-leg-int-tgl",
        P_Ven_Ltgl_Only: "ot-leg-int-tgl-only",
        P_Ven_Opts: ".vendor-options",
        P_Triangle: "#ot-triangle",
        P_Fltr_Modal: "#ot-filter-modal",
        P_Fltr_Options: ".ot-group-options",
        P_Fltr_Option: ".ot-group-option",
        P_Select_Cntr: "#select-all-container",
        P_Host_Cntr: "#hosts-list-container",
        P_Host_Hdr: ".host-info",
        P_Host_Desc: ".host-description",
        P_Host_Opt: ".host-option-group",
        P_Host_Info: ".vendor-host",
        P_Ven_Dets: ".vendor-purpose-groups",
        P_Ven_Disc: ".ot-ven-disc",
        P_Gven_List: "#ot-gn-venlst",
        P_Arrw_Cntr: ".ot-arrow-container",
        P_Li_Hdr: ".leg-int-header",
        P_Li_Title: ".leg-int-title",
        P_Acc_Txt: ".accordion-text",
        P_Tgl_Cntr: ".ot-toggle-group",
        P_CBx_Cntr: ".ot-chkbox-container",
        P_Host_Title: ".host-title",
        P_Leg_Select_All: ".leg-int-sel-all-hdr",
        P_Leg_Header: ".leg-int-hdr",
        P_Cnsnt_Header: ".consent-hdr",
        P_Acc_Header: ".accordion-header",
        P_Sel_All_Vendor_Consent_Handler: "#select-all-vendor-leg-handler",
        P_Sel_All_Vendor_Leg_Handler: "#select-all-vendor-groups-handler",
        P_Sel_All_Host_Handler: "#select-all-hosts-groups-handler",
        P_Sel_All_Host_El: "select-all-hosts-input-container",
        P_Sel_All_Vendor_Consent_El: "select-all-vendors-input-container",
        P_Sel_All_Vendor_Leg_El: "select-all-vendors-leg-input-container",
        P_c_Name: "cookie-name-container",
        P_c_Host: "cookie-host-container",
        P_c_Duration: "cookie-duration-container",
        P_c_Type: "cookie-type-container",
        P_c_Category: "cookie-category-container",
        P_c_Desc: "cookie-description-container",
        P_Host_View_Cookies: ".host-view-cookies",
        P_Vendor_CheckBx: "vendor-chkbox",
        P_Vendor_LegCheckBx: "vendor-leg-chkbox",
        P_Host_UI: "hosts-list",
        P_Host_Cnt: "host-list-content",
        P_Host_Bx: "host-box",
        P_Ven_Lst_Cntr: ".category-vendors-list-container",
        P_Host_Lst_cntr: ".category-host-list-container",
        P_Subgrp_Desc: ".cookie-subgroups-description-legal",
        P_Subgp_ul: ".cookie-subgroups",
        P_Subgrp_li: ".cookie-subgroup",
        P_Subgrp_Tgl_Cntr: ".cookie-subgroup-toggle",
        P_Active_Menu: "active-group",
        P_Tab_Grp_Hdr: "group-toggle",
        P_Search_Cntr: "#search-container",
        P_Clr_Fltr_Txt: "#clear-filters-handler p",
        P_Vendor_Search_Input: "#vendor-search-handler"
    };
    function Yt() {}
    var Xt, Qt = new (Yt.prototype.initializeBannerVariables = function(e) {
        var t, o = e.DomainData;
        Ot.iabType = o.IabType,
        t = o.PCTemplateUpgrade,
        Kt = t ? Wt : Jt,
        Ot.init(e),
        Ht.showGeneralVendors = Nt.GeneralVendorsEnabled && Nt.PCTemplateUpgrade,
        Ht.showVendorService = It.fp.CookieV2VendorServiceScript && Nt.VendorServiceConfig.PCVSEnable && "IAB2" !== Nt.IabType && Nt.PCTemplateUpgrade,
        Ht.vsIsActiveAndOptOut = Ht.showVendorService && Nt.VendorServiceConfig.PCVSOptOut,
        Ht.genVenOptOutEnabled = Ht.showGeneralVendors && Nt.GenVenOptOut,
        Mt.addLogoUrls(),
        this.setGeolocationInCookies(),
        this.setOrUpdate3rdPartyIABConsentFlag()
    }
    ,
    Yt.prototype.initializeVendorInOverriddenVendors = function(e, t) {
        Nt.OverriddenVendors[e] = {
            disabledCP: [],
            disabledLIP: [],
            active: t,
            legInt: !1,
            consent: !1
        }
    }
    ,
    Yt.prototype.applyGlobalRestrictionsonNewVendor = function(e, t, o, n) {
        var r = Nt.GlobalRestrictions
          , i = Nt.OverriddenVendors;
        switch (i[t] || this.initializeVendorInOverriddenVendors(t, !0),
        i[t].disabledCP || (i[t].disabledCP = []),
        i[t].disabledLIP || (i[t].disabledLIP = []),
        r[o]) {
        case q.Disabled:
            n ? i[t].disabledCP.push(o) : i[t].disabledLIP.push(o),
            Nt.Publisher.restrictions[o][t] = q.Disabled;
            break;
        case q.Consent:
            n ? (i[t].consent = !0,
            Nt.Publisher.restrictions[o][t] = q.Consent) : (i[t].disabledLIP.push(o),
            this.checkFlexiblePurpose(e, t, o, !1));
            break;
        case q.LegInt:
            n ? (i[t].disabledCP.push(o),
            this.checkFlexiblePurpose(e, t, o, !0)) : (i[t].legInt = !0,
            Nt.Publisher.restrictions[o][t] = q.LegInt);
            break;
        case void 0:
            n ? i[t].consent = !0 : i[t].legInt = !0
        }
    }
    ,
    Yt.prototype.checkFlexiblePurpose = function(e, t, o, n) {
        e.flexiblePurposes.includes(o) ? (n ? Nt.OverriddenVendors[t].legInt = !0 : Nt.OverriddenVendors[t].consent = !0,
        Nt.Publisher.restrictions[o][t] = n ? q.LegInt : q.Consent) : Nt.Publisher.restrictions[o][t] = q.Disabled
    }
    ,
    Yt.prototype.removeInActiveVendorsForTcf = function(i) {
        var s = this
          , a = Ht.iabData.vendorListVersion
          , e = Nt.Publisher
          , l = Nt.GlobalRestrictionEnabled
          , c = !(0 === Object.keys(e).length || e && 0 === Object.keys(e.restrictions).length);
        Object.keys(i.vendors).forEach(function(t) {
            var o = i.vendors[t];
            o.iab2GVLVersion > a && (Nt.NewVendorsInactiveEnabled ? s.initializeVendorInOverriddenVendors(t, !1) : l && (o.purposes.forEach(function(e) {
                s.applyGlobalRestrictionsonNewVendor(o, t, e, !0)
            }),
            o.legIntPurposes.forEach(function(e) {
                s.applyGlobalRestrictionsonNewVendor(o, t, e, !1)
            })));
            var e = !1;
            Nt.IsIabThirdPartyCookieEnabled || (Ot.legIntSettings.PAllowLI ? Nt.OverriddenVendors[t] && !Nt.OverriddenVendors[t].active && (e = !0) : -1 < Nt.Vendors.indexOf(Number(t)) && (e = !0));
            var n = !o.purposes.length && !o.flexiblePurposes.length;
            Nt.OverriddenVendors[t] && !Nt.OverriddenVendors[t].consent && (n = !0);
            var r = !0;
            Ot.legIntSettings.PAllowLI && (!o.legIntPurposes.length || Nt.OverriddenVendors[t] && !Nt.OverriddenVendors[t].legInt || (r = !1)),
            !n || !r || o.specialPurposes.length || o.features.length || o.specialFeatures.length || (e = !0),
            !l && c && o.iab2GVLVersion > a && (e = !0),
            e && delete i.vendors[t]
        })
    }
    ,
    Yt.prototype.setPublisherRestrictions = function() {
        var e = Nt.Publisher;
        if (e && e.restrictions) {
            var s = this.iabStringSDK()
              , t = e.restrictions
              , a = Ht.iabData
              , l = Ht.oneTrustIABConsent.vendorList.vendors;
            Object.keys(t).forEach(function(n) {
                var r, i = t[n], e = Ot.iabGroups.purposes[n];
                e && (r = {
                    description: e.description,
                    purposeId: e.id,
                    purposeName: e.name
                }),
                Object.keys(i).forEach(function(e) {
                    if (Ht.vendorsSetting[e]) {
                        var t = Ht.vendorsSetting[e].arrIndex;
                        1 === i[e] && -1 === l[e].purposes.indexOf(Number(n)) ? a.vendors[t].purposes.push(r) : 2 === i[e] && -1 === l[e].legIntPurposes.indexOf(Number(n)) && a.vendors[t].legIntPurposes.push(r);
                        var o = s.purposeRestriction(Number(n), i[e]);
                        Ht.tcModel.publisherRestrictions.add(Number(e), o)
                    }
                })
            })
        }
    }
    ,
    Yt.prototype.populateVendorListTCF = function() {
        return c(this, void 0, void 0, function() {
            var t, o, n, r, i, s, a, l, c;
            return C(this, function(e) {
                switch (e.label) {
                case 0:
                    return t = this.iabStringSDK(),
                    o = Ht.iabData,
                    n = Mt.updateCorrectIABUrl(o.globalVendorListUrl),
                    r = !this.isIABCrossConsentEnabled(),
                    Mt.checkMobileOfflineRequest(Mt.getBannerVersionUrl()) ? [3, 1] : (Ot.mobileOnlineURL.push(n),
                    i = t.gvl(n, Ht.gvlObj),
                    [3, 3]);
                case 1:
                    return a = (s = t).gvl,
                    l = [null],
                    [4, Mt.otFetchOfflineFile(Bt.getRelativeURL(n, !0))];
                case 2:
                    i = a.apply(s, l.concat([e.sent()])),
                    e.label = 3;
                case 3:
                    return this.removeInActiveVendorsForTcf(i),
                    Ht.oneTrustIABConsent.vendorList = i,
                    this.assignIABDataWithGlobalVendorList(i),
                    c = Ht,
                    [4, t.tcModel(i)];
                case 4:
                    c.tcModel = e.sent(),
                    r && this.setPublisherRestrictions(),
                    Ht.tcModel.cmpId = parseInt(o.cmpId),
                    Ht.tcModel.cmpVersion = parseInt(o.cmpVersion);
                    try {
                        Ht.tcModel.consentLanguage = Ht.consentLanguage
                    } catch (e) {
                        Ht.tcModel.consentLanguage = "EN"
                    }
                    return Ht.tcModel.consentScreen = parseInt(o.consentScreen),
                    Ht.tcModel.isServiceSpecific = r,
                    Ht.tcModel.purposeOneTreatment = Ot.purposeOneTreatment,
                    Nt.PublisherCC ? Ht.tcModel.publisherCountryCode = Nt.PublisherCC : Ht.userLocation.country && (Ht.tcModel.publisherCountryCode = Ht.userLocation.country),
                    Ht.cmpApi = t.cmpApi(Ht.tcModel.cmpId, Ht.tcModel.cmpVersion, r, Nt.UseGoogleVendors ? {
                        getTCData: this.addtlConsentString,
                        getInAppTCData: this.addtlConsentString
                    } : void 0),
                    null !== this.alertBoxCloseDate() && !this.needReconsent() || this.resetTCModel(),
                    [2]
                }
            })
        })
    }
    ,
    Yt.prototype.resetTCModel = function() {
        var e = this.iabStringSDK()
          , t = Ht.tcModel.clone();
        if (t.unsetAll(),
        Ot.legIntSettings.PAllowLI) {
            var o = Ot.consentableIabGrps.filter(function(e) {
                return e.HasLegIntOptOut && e.Type === ft
            }).map(function(e) {
                return parseInt(Ot.iabGrpIdMap[e.CustomGroupId])
            })
              , n = Object.keys(Ht.vendorsSetting).filter(function(e) {
                return Ht.vendorsSetting[e].legInt
            }).map(function(e) {
                return parseInt(e)
            });
            t.purposeLegitimateInterests.set(o),
            t.vendorLegitimateInterests.set(n),
            t.isServiceSpecific && t.publisherLegitimateInterests.set(o)
        }
        Ht.cmpApi.update(e.tcString().encode(t), !0)
    }
    ,
    Yt.prototype.addtlConsentString = function(e, t, o) {
        t && (t.addtlConsent = "" + Ht.addtlConsentVersion + (Ht.isAddtlConsent ? Ht.addtlVendors.vendorConsent.join(".") : "")),
        "function" == typeof e ? e(t, o) : console.error("__tcfapi received invalid parameters.")
    }
    ,
    Yt.prototype.setIabData = function() {
        Ht.iabData = It.moduleInitializer.IabV2Data,
        Ht.iabData.consentLanguage = Ht.consentLanguage
    }
    ,
    Yt.prototype.assignIABDataWithGlobalVendorList = function(r) {
        var i = Nt.OverriddenVendors;
        Ht.iabData.vendorListVersion = r.vendorListVersion,
        Ht.iabData.vendors = [],
        Object.keys(r.vendors).forEach(function(n) {
            Ht.vendorsSetting[n] = {
                consent: !0,
                legInt: !0,
                arrIndex: 0,
                specialPurposesOnly: !1
            };
            var e = {}
              , t = r.vendors[n];
            e.vendorId = n,
            e.vendorName = t.name,
            e.policyUrl = t.policyUrl,
            e.cookieMaxAge = Bt.calculateCookieLifespan(t.cookieMaxAgeSeconds),
            e.usesNonCookieAccess = t.usesNonCookieAccess,
            e.deviceStorageDisclosureUrl = t.deviceStorageDisclosureUrl || null;
            var o = !t.legIntPurposes.length && !t.purposes.length && t.specialPurposes.length;
            Ot.legIntSettings.PAllowLI && ((!i[n] || i[n].legInt) && (i[n] || t.legIntPurposes.length) || o) || (Ht.vendorsSetting[n].legInt = !1),
            Ot.legIntSettings.PAllowLI && o && (Ht.vendorsSetting[n].specialPurposesOnly = !0),
            i[n] && !i[n].consent || !i[n] && !t.purposes.length && !t.flexiblePurposes.length ? Ht.vendorsSetting[n].consent = !1 : t.purposes.length || t.flexiblePurposes.length || (Ht.vendorsSetting[n].consent = !1),
            e.features = t.features.map(function(e) {
                var t, o = Ot.iabGroups.features[e];
                return o && (t = {
                    description: o.description,
                    featureId: o.id,
                    featureName: o.name
                }),
                t
            }),
            e.specialFeatures = r.vendors[n].specialFeatures.reduce(function(e, t) {
                var o = Ot.iabGroups.specialFeatures[t];
                return o && e.push({
                    description: o.description,
                    featureId: o.id,
                    featureName: o.name
                }),
                e
            }, []),
            e.purposes = r.vendors[n].purposes.reduce(function(e, t) {
                var o = Ot.iabGroups.purposes[t];
                return !o || i[n] && i[n].disabledCP && -1 !== i[n].disabledCP.indexOf(t) || e.push({
                    description: o.description,
                    purposeId: o.id,
                    purposeName: o.name
                }),
                e
            }, []),
            e.legIntPurposes = r.vendors[n].legIntPurposes.reduce(function(e, t) {
                var o = Ot.iabGroups.purposes[t];
                return !o || i[n] && i[n].disabledLIP && -1 !== i[n].disabledLIP.indexOf(t) || e.push({
                    description: o.description,
                    purposeId: o.id,
                    purposeName: o.name
                }),
                e
            }, []),
            e.specialPurposes = t.specialPurposes.map(function(e) {
                var t, o = Ot.iabGroups.specialPurposes[e];
                return o && (t = {
                    description: o.description,
                    purposeId: o.id,
                    purposeName: o.name
                }),
                t
            }),
            Ht.iabData.vendors.push(e),
            Ht.vendorsSetting[n].arrIndex = Ht.iabData.vendors.length - 1
        })
    }
    ,
    Yt.prototype.populateIABCookies = function() {
        return c(this, void 0, void 0, function() {
            return C(this, function(e) {
                switch (e.label) {
                case 0:
                    if (!this.isIABCrossConsentEnabled())
                        return [3, 5];
                    e.label = 1;
                case 1:
                    return e.trys.push([1, 3, , 4]),
                    [4, this.setIAB3rdPartyCookie(Ee.EU_CONSENT, "", 0, !0)];
                case 2:
                    return e.sent(),
                    [3, 4];
                case 3:
                    return e.sent(),
                    this.setIABCookieData(),
                    this.updateCrossConsentCookie(!1),
                    [3, 4];
                case 4:
                    return [3, 6];
                case 5:
                    Qt.needReconsent() || this.setIABCookieData(),
                    e.label = 6;
                case 6:
                    return [2]
                }
            })
        })
    }
    ,
    Yt.prototype.setIAB3rdPartyCookie = function(e, t, o, n) {
        var r = Nt.iabThirdPartyConsentUrl;
        try {
            if (r && document.body)
                return this.updateThirdPartyConsent(r, e, t, o, n);
            throw new ReferenceError
        } catch (e) {
            throw e
        }
    }
    ,
    Yt.prototype.setIABCookieData = function() {
        Ht.oneTrustIABConsent.IABCookieValue = Vt.getCookie(Ee.EU_PUB_CONSENT)
    }
    ,
    Yt.prototype.updateThirdPartyConsent = function(n, r, i, s, a) {
        return c(this, void 0, void 0, function() {
            var t, o;
            return C(this, function(e) {
                return t = window.location.protocol + "//" + n + "/?name=" + r + "&value=" + i + "&expire=" + s + "&isFirstRequest=" + a,
                document.getElementById("onetrustIabCookie") ? (document.getElementById("onetrustIabCookie").contentWindow.location.replace(t),
                [2]) : (Lt(o = document.createElement("iframe"), "display: none;", !0),
                o.id = "onetrustIabCookie",
                o.setAttribute("title", "OneTrust IAB Cookie"),
                o.src = t,
                document.body.appendChild(o),
                [2, new Promise(function(e) {
                    o.onload = function() {
                        Ot.thirdPartyiFrameResolve(),
                        Ot.thirdPartyiFrameLoaded = !0,
                        e()
                    }
                    ,
                    o.onerror = function() {
                        throw Ot.thirdPartyiFrameResolve(),
                        Ot.thirdPartyiFrameLoaded = !0,
                        e(),
                        new URIError
                    }
                }
                )])
            })
        })
    }
    ,
    Yt.prototype.setIABVendor = function(n) {
        if (void 0 === n && (n = !0),
        Ht.iabData.vendors.forEach(function(e) {
            var t = e.vendorId;
            if (Ot.legIntSettings.PAllowLI) {
                var o = !Ht.vendorsSetting[t].consent;
                Ht.oneTrustIABConsent.vendors.push(t.toString() + ":" + (o ? "false" : n)),
                Ht.oneTrustIABConsent.legIntVendors.push(t.toString() + ":" + Ht.vendorsSetting[t].legInt)
            } else
                Ht.oneTrustIABConsent.legIntVendors = [],
                Ht.oneTrustIABConsent.vendors.push(t.toString() + ":" + n)
        }),
        Nt.UseGoogleVendors) {
            var t = Ht.addtlVendors;
            Object.keys(Ht.addtlVendorsList).forEach(function(e) {
                n && (t.vendorSelected["" + e.toString()] = !0,
                t.vendorConsent.push("" + e.toString()))
            })
        }
    }
    ,
    Yt.prototype.setOrUpdate3rdPartyIABConsentFlag = function() {
        var e = this.getIABCrossConsentflagData();
        Nt.IsIabEnabled ? e && !this.needReconsent() || this.updateCrossConsentCookie(Nt.IsIabThirdPartyCookieEnabled) : e && !this.reconsentRequired() && "true" !== e || this.updateCrossConsentCookie(!1)
    }
    ,
    Yt.prototype.isIABCrossConsentEnabled = function() {
        return "true" === this.getIABCrossConsentflagData()
    }
    ,
    Yt.prototype.getIABCrossConsentflagData = function() {
        return Vt.readCookieParam(Ee.OPTANON_CONSENT, _e)
    }
    ,
    Yt.prototype.setGeolocationInCookies = function() {
        var e = Vt.readCookieParam(Ee.OPTANON_CONSENT, Ie);
        if (Ht.userLocation && !e && this.isAlertBoxClosedAndValid()) {
            var t = Ht.userLocation.country + ";" + Ht.userLocation.state;
            this.setUpdateGeolocationCookiesData(t)
        } else
            this.reconsentRequired() && e && this.setUpdateGeolocationCookiesData("")
    }
    ,
    Yt.prototype.iabStringSDK = function() {
        var e = It.moduleInitializer.otIABModuleData;
        if (Nt.IsIabEnabled && e)
            return {
                gvl: e.tcfSdkRef.gvl,
                tcModel: e.tcfSdkRef.tcModel,
                tcString: e.tcfSdkRef.tcString,
                cmpApi: e.tcfSdkRef.cmpApi,
                purposeRestriction: e.tcfSdkRef.purposeRestriction
            }
    }
    ,
    Yt.prototype.setUpdateGeolocationCookiesData = function(e) {
        Vt.writeCookieParam(Ee.OPTANON_CONSENT, Ie, e)
    }
    ,
    Yt.prototype.reconsentRequired = function() {
        return (It.moduleInitializer.MobileSDK || this.awaitingReconsent()) && this.needReconsent()
    }
    ,
    Yt.prototype.awaitingReconsent = function() {
        return "true" === Vt.readCookieParam(Ee.OPTANON_CONSENT, Ae)
    }
    ,
    Yt.prototype.needReconsent = function() {
        var e = this.alertBoxCloseDate()
          , t = Nt.LastReconsentDate;
        return e && t && new Date(t) > new Date(e)
    }
    ,
    Yt.prototype.updateCrossConsentCookie = function(e) {
        Vt.writeCookieParam(Ee.OPTANON_CONSENT, _e, e)
    }
    ,
    Yt.prototype.alertBoxCloseDate = function() {
        return Vt.getCookie(Ee.ALERT_BOX_CLOSED)
    }
    ,
    Yt.prototype.isAlertBoxClosedAndValid = function() {
        return null !== this.alertBoxCloseDate() && !this.reconsentRequired()
    }
    ,
    Yt.prototype.generateLegIntButtonElements = function(e, t, o) {
        void 0 === o && (o = !1);
        var n = e ? "display:none;" : "";
        return '<div class="ot-leg-btn-container" data-group-id="' + t + '" data-el-id="' + t + '-leg-out" is-vendor="' + o + '">\n                    <button class="ot-obj-leg-btn-handler ' + (e ? "ot-leg-int-enabled ot-inactive-leg-btn" : "ot-active-leg-btn") + '">\n                        <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" x="0px" y="0px" viewBox="0 0 512 512">\n                            <path fill="' + Nt.pcButtonTextColor + '" d="M173.898 439.404l-166.4-166.4c-9.997-9.997-9.997-26.206 0-36.204l36.203-36.204c9.997-9.998 26.207-9.998 36.204 0L192 312.69 432.095 72.596c9.997-9.997 26.207-9.997 36.204 0l36.203 36.204c9.997 9.997 9.997 26.206 0 36.204l-294.4 294.401c-9.998 9.997-26.207 9.997-36.204-.001z"/>\n                        </svg>\n                        <span>' + (e ? Ot.legIntSettings.PObjectLegIntText : Ot.legIntSettings.PObjectionAppliedText) + '\n                        </span>\n                    </button>\n                    <button\n                        class="ot-remove-objection-handler"\n                            data-style="color:' + Nt.pcButtonColor + "; " + n + '"\n                    >\n                        ' + Ot.legIntSettings.PRemoveObjectionText + "\n                    </button>\n                </div>"
    }
    ,
    Yt.prototype.syncAlertBoxCookie = function(e) {
        var t = Nt.ReconsentFrequencyDays;
        Vt.setCookie(Ee.ALERT_BOX_CLOSED, e, t, !1, new Date(e))
    }
    ,
    Yt.prototype.syncCookieExpiry = function() {
        if (Ht.syncRequired) {
            var e = Nt.ReconsentFrequencyDays
              , t = Vt.getCookie(Ee.ALERT_BOX_CLOSED)
              , o = Vt.getCookie(Ee.OPTANON_CONSENT);
            Vt.setCookie(Ee.OPTANON_CONSENT, o, e, !1, new Date(t)),
            Qt.needReconsent() && Vt.removeAlertBox();
            var n = Vt.getCookie(Ee.EU_PUB_CONSENT);
            n && (Qt.isIABCrossConsentEnabled() ? Vt.removeIab2() : Vt.setCookie(Ee.EU_PUB_CONSENT, n, e, !1, new Date(t)));
            var r = Vt.getCookie(Ee.ADDITIONAL_CONSENT_STRING);
            r && Vt.setCookie(Ee.ADDITIONAL_CONSENT_STRING, r, e, !1, new Date(t))
        }
    }
    ,
    Yt.prototype.syncOtPreviewCookie = function() {
        var e = Vt.getCookie(Ee.OT_PREVIEW);
        e && Vt.setCookie(Ee.OT_PREVIEW, e, 1, !1)
    }
    ,
    Yt.prototype.dispatchConsentEvent = function() {
        window.dispatchEvent(new CustomEvent("OTConsentApplied",{
            OTConsentApplied: "yes"
        }))
    }
    ,
    Yt), $t = (Zt.prototype.isAlwaysActiveGroup = function(e) {
        if (this.getGrpStatus(e)) {
            var t = this.getGrpStatus(e).toLowerCase();
            return e.Parent && t !== De && (t = this.getGrpStatus(this.getParentGroup(e.Parent)).toLowerCase()),
            t === De
        }
        return !0
    }
    ,
    Zt.prototype.getGrpStatus = function(e) {
        return e && e.Status ? Ot.DNTEnabled && e.IsDntEnabled ? qe : e.Status : ""
    }
    ,
    Zt.prototype.getParentGroup = function(t) {
        if (t) {
            var e = Nt.Groups.filter(function(e) {
                return e.OptanonGroupId === t
            });
            return 0 < e.length ? e[0] : null
        }
        return null
    }
    ,
    Zt.prototype.checkIfGroupHasConsent = function(t) {
        var e = Ht.groupsConsent
          , o = Bt.findIndex(e, function(e) {
            return e.split(":")[0] === t.CustomGroupId
        });
        return -1 < o && "1" === e[o].split(":")[1]
    }
    ,
    Zt.prototype.checkIsActiveByDefault = function(e) {
        if (this.getGrpStatus(e)) {
            var t = this.getGrpStatus(e).toLowerCase();
            return e.Parent && t !== De && (t = this.getGrpStatus(this.getParentGroup(e.Parent)).toLowerCase()),
            t === De || t === Fe || t === He || t === qe && !Ot.DNTEnabled
        }
        return !0
    }
    ,
    Zt.prototype.getGroupById = function(e) {
        for (var t = null, o = 0, n = Nt.Groups; o < n.length; o++) {
            for (var r = n[o], i = 0, s = y(r.SubGroups, [r]); i < s.length; i++) {
                var a = s[i];
                if (a.CustomGroupId === e) {
                    t = a;
                    break
                }
            }
            if (t)
                break
        }
        return t
    }
    ,
    Zt.prototype.isSoftOptInGrp = function(e) {
        if (e) {
            var t = e && !e.Parent ? e : Xt.getParentGroup(e.Parent);
            return "inactive landingpage" === Xt.getGrpStatus(t).toLowerCase()
        }
        return !1
    }
    ,
    Zt.prototype.isOptInGrp = function(e) {
        return !!e && "inactive" === Xt.getGrpStatus(e).toLowerCase()
    }
    ,
    Zt.prototype.getParentByGrp = function(e) {
        return e.Parent ? this.getGroupById(e.Parent) : null
    }
    ,
    Zt.prototype.getVSById = function(e) {
        return Ht.getVendorsInDomain().get(e)
    }
    ,
    Zt.prototype.getGrpByVendorId = function(e) {
        var t = null;
        return Ht.getVendorsInDomain().has(e) && (t = Ht.getVendorsInDomain().get(e).groupRef),
        t
    }
    ,
    Zt);
    function Zt() {}
    var eo, to = (oo.prototype.ensureConsentId = function(e, t) {
        var o, n = !1, r = Vt.readCookieParam(Ee.OPTANON_CONSENT, Te, !0);
        if (o = !e && t ? (n = !0,
        1) : 0,
        r) {
            var i = parseInt(Vt.readCookieParam(Ee.OPTANON_CONSENT, Le), 10);
            isNaN(i) || (o = t ? ++i : i,
            n = !1)
        } else
            r = Bt.generateUUID(),
            Vt.writeCookieParam(Ee.OPTANON_CONSENT, Te, r);
        return Vt.writeCookieParam(Ee.OPTANON_CONSENT, Le, o),
        {
            id: r,
            count: o,
            addDfltInt: n
        }
    }
    ,
    oo.prototype.isAnonymousConsent = function() {
        var e = !0
          , t = Ht.dsParams;
        return t && t.hasOwnProperty("isAnonymous") && (e = t.isAnonymous),
        e
    }
    ,
    oo.prototype.isAuthUsr = function(e) {
        Ht.consentPreferences ? Vt.writeCookieParam(Ee.OPTANON_CONSENT, "iType", "") : Vt.writeCookieParam(Ee.OPTANON_CONSENT, "iType", "" + U[e])
    }
    ,
    oo.prototype.createConsentTxn = function(e, t, o, n) {
        void 0 === t && (t = ""),
        void 0 === o && (o = !1),
        void 0 === n && (n = !0);
        var r = this.ensureConsentId(e, n)
          , i = Nt.ConsentIntegration
          , s = window.navigator.userAgent
          , a = /OneTrustBot/.test(s);
        if (i.ConsentApi && i.RequestInformation && r.id && !a) {
            var l = It.moduleInitializer;
            eo.noOptOutToogle = l.TenantFeatures.CookieV2NoOptOut;
            var c = Ht.bannerCloseSource;
            eo.isCloseByIconOrLink = c === f.BannerCloseButton || c === f.ContinueWithoutAcceptingButton;
            var d = {
                requestInformation: i.RequestInformation,
                identifier: r.id,
                customPayload: {
                    Interaction: r.count,
                    AddDefaultInteraction: r.addDfltInt
                },
                isAnonymous: this.isAnonymousConsent(),
                test: l.ScriptType === Ue || l.ScriptType === je,
                purposes: this.getConsetPurposes(e),
                dsDataElements: {}
            };
            Ht.isV2Stub && (d.syncGroup = Ht.syncGrpId,
            "IAB2" !== Ot.iabType || Qt.isIABCrossConsentEnabled() || (d.tcStringV2 = Vt.getCookie(Ee.EU_PUB_CONSENT)),
            Nt.UseGoogleVendors && (d.gacString = Vt.getCookie(Ee.ADDITIONAL_CONSENT_STRING)));
            var u = Xt.getGroupById(Nt.AdvancedAnalyticsCategory);
            if (u && this.canSendAdvancedAnalytics(d.purposes, u) && (d.dsDataElements = {
                InteractionType: t,
                Country: Ht && Ht.userLocation ? Ht.userLocation.country : "",
                UserAgent: s
            }),
            !l.MobileSDK && n && d.purposes.length) {
                var p = JSON.stringify(d);
                e && navigator.sendBeacon ? (navigator.sendBeacon(i.ConsentApi, p),
                Qt.dispatchConsentEvent()) : !o && Ot.apiSource !== P.UpdateConsent && Ht.consentInteractionType === t || (Ht.isV2Stub && t && this.isAuthUsr(t),
                Ft.ajax({
                    url: i.ConsentApi,
                    type: "post",
                    dataType: "json",
                    contentType: "application/json",
                    data: JSON.stringify(d),
                    sync: e,
                    success: function() {
                        Qt.dispatchConsentEvent()
                    },
                    error: function() {
                        Qt.dispatchConsentEvent()
                    }
                }))
            }
            Ot.pubDomainData.ConsentIntegrationData = {
                consentApi: i.ConsentApi,
                consentPayload: d
            }
        }
        Ht.consentInteractionType = t
    }
    ,
    oo.prototype.getGrpDetails = function(e, i) {
        var s = [];
        return e.forEach(function(e) {
            var t = e.split(":")
              , o = t[0]
              , n = "true" === t[1] ? "1" : "0"
              , r = eo.getOptanonIdForIabGroup(o, i);
            s.push(r + ":" + n)
        }),
        s
    }
    ,
    oo.prototype.getOptanonIdForIabGroup = function(e, t) {
        var o;
        return t === A.Purpose ? o = "IABV2_" + e : t === A.SpecialFeature && (o = "ISFV2_" + e),
        o
    }
    ,
    oo.prototype.getConsetPurposes = function(r) {
        var e, t, i = this, s = [], o = [], n = Ht.oneTrustIABConsent;
        return e = n && n.purpose ? this.getGrpDetails(n.purpose, A.Purpose) : [],
        t = n && n.specialFeatures ? this.getGrpDetails(n.specialFeatures, A.SpecialFeature) : [],
        o = y(n.specialPurposes, n.features),
        y(Ht.groupsConsent, e, t).forEach(function(e) {
            var t = e.split(":")
              , o = Xt.getGroupById(t[0]);
            if (o && o.PurposeId) {
                var n = i.getTransactionType(o, t, r);
                s.push({
                    Id: o.PurposeId,
                    TransactionType: n.txnType
                }),
                i.setVSConsentByGroup(o, n).forEach(function(e) {
                    return s.push(e)
                })
            }
        }),
        o.forEach(function(e) {
            e.purposeId && s.push({
                Id: e.purposeId,
                TransactionType: Ge
            })
        }),
        Ht.bannerCloseSource = f.Unknown,
        s
    }
    ,
    oo.prototype.setVSConsentByGroup = function(e, o) {
        var n = [];
        return Ht.showVendorService && e.VendorServices && e.VendorServices.forEach(function(e) {
            var t;
            t = o.useOwn ? Ht.vsConsent.get(e.CustomVendorServiceId) ? we : xe : o.txnType,
            n.push({
                Id: e.PurposeId,
                TransactionType: t
            })
        }),
        n
    }
    ,
    oo.prototype.getTransactionType = function(e, t, o) {
        var n = {
            txnType: Ge,
            useOwn: !1
        };
        return e.Status === De ? n.txnType = Ge : e.Status === Re && eo.isCloseByIconOrLink || o ? n.txnType = Oe : e.Status === He && eo.isCloseByIconOrLink ? n.txnType = eo.noOptOutToogle ? Ne : we : (n.useOwn = !0,
        n.txnType = this.getTxnType(t[1])),
        n
    }
    ,
    oo.prototype.getTxnType = function(e) {
        return "0" === e ? xe : we
    }
    ,
    oo.prototype.isPurposeConsentedTo = function(e, t) {
        var o = [we, Ge];
        return e.some(function(e) {
            return e.Id === t.PurposeId && -1 !== o.indexOf(e.TransactionType)
        })
    }
    ,
    oo.prototype.canSendAdvancedAnalytics = function(t, e) {
        var o = this;
        return "BRANCH" === e.Type || "IAB2_STACK" === e.Type ? e.SubGroups.length && e.SubGroups.every(function(e) {
            return o.isPurposeConsentedTo(t, e)
        }) : this.isPurposeConsentedTo(t, e)
    }
    ,
    oo);
    function oo() {}
    var no, ro = (io.prototype.isIabCookieValid = function() {
        var e = null;
        switch (Ot.iabType) {
        case "IAB2":
            e = Vt.getCookie("eupubconsent-v2")
        }
        return null !== e
    }
    ,
    io.prototype.iabTypeIsChanged = function() {
        this.isIabCookieValid() || (Vt.removeAlertBox(),
        Vt.removeIab1())
    }
    ,
    io.prototype.initializeIABModule = function() {
        return c(this, void 0, void 0, function() {
            return C(this, function(e) {
                switch (e.label) {
                case 0:
                    return Nt.IsIabEnabled ? (It.moduleInitializer.otIABModuleData = window.otIabModule,
                    Qt.setIabData(),
                    [4, Qt.populateVendorListTCF()]) : [3, 2];
                case 1:
                    return e.sent(),
                    Qt.isIABCrossConsentEnabled() || this.iabTypeIsChanged(),
                    Qt.populateIABCookies(),
                    Nt.UseGoogleVendors && this.removeInActiveAddtlVendors(),
                    [3, 3];
                case 2:
                    Vt.removeIab1(),
                    e.label = 3;
                case 3:
                    return [2]
                }
            })
        })
    }
    ,
    io.prototype.removeInActiveAddtlVendors = function() {
        var e = Nt.OverridenGoogleVendors;
        for (var t in Ht.addtlVendorsList)
            e && e[t] && !e[t].active && delete Ht.addtlVendorsList[t]
    }
    ,
    io.prototype.getIABConsentData = function() {
        var e = Ht.oneTrustIABConsent
          , t = Qt.iabStringSDK().tcString();
        Ht.tcModel.unsetAllPurposeConsents(),
        Ht.tcModel.unsetAllVendorConsents(),
        Ht.tcModel.unsetAllVendorLegitimateInterests(),
        Ht.tcModel.unsetAllSpecialFeatureOptins(),
        Ht.tcModel.unsetAllPurposeLegitimateInterests(),
        Ht.tcModel.publisherConsents.empty(),
        Ht.tcModel.publisherLegitimateInterests.empty(),
        Ht.tcModel.purposeConsents.set(Bt.getActiveIdArray(e.purpose)),
        Ht.tcModel.publisherConsents.set(Bt.getActiveIdArray(e.purpose));
        var o = Ot.legIntSettings.PAllowLI ? Bt.getActiveIdArray(e.legimateInterest) : [];
        Ht.tcModel.purposeLegitimateInterests.set(o),
        Ht.tcModel.publisherLegitimateInterests.set(o),
        Ht.tcModel.vendorConsents.set(Bt.getActiveIdArray(Bt.distinctArray(e.vendors))),
        Ot.legIntSettings.PAllowLI && !o.length && (e.legIntVendors = []),
        Ht.tcModel.vendorLegitimateInterests.set(Bt.getActiveIdArray(Bt.distinctArray(e.legIntVendors))),
        Ht.tcModel.specialFeatureOptins.set(Bt.getActiveIdArray(e.specialFeatures));
        var n = new Date
          , r = new Date(n.getUTCFullYear(),n.getUTCMonth(),n.getUTCDate(),0,0,0);
        Ht.tcModel.lastUpdated = r,
        Ht.tcModel.created = r;
        var i = t.encode(Ht.tcModel);
        return Ht.cmpApi.update(i, !1),
        i
    }
    ,
    io.prototype.decodeTCString = function(e) {
        return Qt.iabStringSDK().tcString().decode(e)
    }
    ,
    io.prototype.getVendorConsentsRequestV2 = function(e) {
        var o;
        return window.__tcfapi("getInAppTCData", 2, function(e, t) {
            o = [e, t]
        }),
        e.apply(this, o)
    }
    ,
    io.prototype.getPingRequestForTcf = function(e) {
        var t;
        return window.__tcfapi("ping", 2, function(e) {
            t = [e]
        }),
        e.apply(this, t)
    }
    ,
    io.prototype.populateVendorAndPurposeFromCookieData = function() {
        var r = Ht.oneTrustIABConsent
          , e = no.decodeTCString(r.IABCookieValue)
          , i = {}
          , s = {};
        Ot.iabGrps.forEach(function(e) {
            e.Type === ft ? i[Ot.iabGrpIdMap[e.CustomGroupId]] = e : e.Type === vt && (s[Ot.iabGrpIdMap[e.CustomGroupId]] = e)
        });
        var a = [];
        e.vendorConsents.forEach(function(e, t) {
            var o = e;
            Ht.vendorsSetting[t] && Ht.vendorsSetting[t].consent || !e || (a.push(t),
            o = !1),
            r.vendors.push(t + ":" + o)
        }),
        e.vendorConsents.unset(a),
        a = [],
        e.vendorLegitimateInterests.forEach(function(e, t) {
            var o = e;
            Ht.vendorsSetting[t] && Ht.vendorsSetting[t].legInt || !e || (a.push(t),
            o = !1),
            r.legIntVendors.push(t + ":" + o)
        }),
        e.vendorLegitimateInterests.unset(a),
        a = [],
        e.purposeConsents.forEach(function(e, o) {
            var t = e;
            i[o] && i[o].HasConsentOptOut || !e || (a.push(o),
            t = !1);
            var n = Bt.findIndex(r.purpose, function(e, t) {
                return e.split(":")[0] === o.toString()
            });
            -1 === n ? r.purpose.push(o + ":" + t) : r.purpose[n] = o + ":" + t
        }),
        e.purposeConsents.unset(a),
        e.publisherConsents.unset(a),
        a = [],
        e.specialFeatureOptins.forEach(function(e, o) {
            var t = e;
            s[o] && s[o].HasConsentOptOut || !e || (a.push(o),
            t = !1);
            var n = Bt.findIndex(r.specialFeatures, function(e, t) {
                return e.split(":")[0] === o.toString()
            });
            -1 === n ? r.specialFeatures.push(o + ":" + t) : r.specialFeatures[n] = o + ":" + t
        }),
        e.specialFeatureOptins.unset(a),
        a = [],
        e.purposeLegitimateInterests.forEach(function(e, o) {
            var t = e;
            i[o] && i[o].HasLegIntOptOut && Ot.legIntSettings.PAllowLI || !e || (a.push(o),
            t = !1);
            var n = Bt.findIndex(r.legimateInterest, function(e, t) {
                return e.split(":")[0] === o.toString()
            });
            -1 === n ? r.legimateInterest.push(o + ":" + t) : r.legimateInterest[n] = o + ":" + t
        }),
        e.purposeLegitimateInterests.unset(a),
        e.publisherLegitimateInterests.unset(a),
        this.syncBundleAndStack(),
        e.gvl = Ht.tcModel.gvl,
        e.isServiceSpecific = !Qt.isIABCrossConsentEnabled(),
        Ht.tcModel = e;
        var t = Qt.iabStringSDK().tcString().encode(e);
        Qt.isAlertBoxClosedAndValid() ? (r.IABCookieValue !== t && (r.IABCookieValue = t,
        Qt.isIABCrossConsentEnabled() ? Qt.setIAB3rdPartyCookie(Ee.EU_CONSENT, r.IABCookieValue, Nt.ReconsentFrequencyDays, !1) : Vt.setCookie(Ee.EU_PUB_CONSENT, r.IABCookieValue, Nt.ReconsentFrequencyDays)),
        Ht.cmpApi.update(t, !1)) : Qt.resetTCModel()
    }
    ,
    io.prototype.syncBundleAndStack = function() {
        var e = Vt.readCookieParam(Ee.OPTANON_CONSENT, "groups");
        Ht.groupsConsent = Bt.strToArr(e),
        Nt.Groups.forEach(function(t) {
            if (t.Type === gt || t.Type === mt) {
                var e = Mt.isBundleOrStackActive(t)
                  , o = Bt.findIndex(Ht.groupsConsent, function(e) {
                    return e.split(":")[0] === t.CustomGroupId
                })
                  , n = t.CustomGroupId + ":" + Number(e);
                -1 < o ? Ht.groupsConsent[o] = n : Ht.groupsConsent.push(n)
            }
        }),
        Vt.writeCookieParam(Ee.OPTANON_CONSENT, "groups", Ht.groupsConsent.join(","))
    }
    ,
    io.prototype.populateGoogleConsent = function() {
        if (Nt.UseGoogleVendors) {
            var e = Vt.getCookie(Ee.ADDITIONAL_CONSENT_STRING);
            e && (Ht.isAddtlConsent = !0,
            Ht.addtlVendors.vendorConsent = e.replace(Ht.addtlConsentVersion, "").split("."))
        }
    }
    ,
    io.prototype.isInitIABCookieData = function(e) {
        return "init" === e || Qt.needReconsent()
    }
    ,
    io.prototype.updateFromGlobalConsent = function(e) {
        var t = Ht.oneTrustIABConsent;
        t.IABCookieValue = e,
        t.purpose = t.purpose || [],
        t.specialFeatures = t.specialFeatures || [],
        t.legIntVendors = [],
        t.legimateInterest = t.legimateInterest || [],
        t.vendors = [],
        no.populateVendorAndPurposeFromCookieData(),
        Vt.setCookie(Ee.EU_PUB_CONSENT, "", -1)
    }
    ,
    io);
    function io() {}
    var so, ao = "groups", lo = "hosts", co = "genVendors", uo = "vs", po = (ho.prototype.writeHstParam = function(e, t) {
        void 0 === t && (t = null),
        Vt.writeCookieParam(e, "hosts", Bt.arrToStr(t || Ht.hostsConsent))
    }
    ,
    ho.prototype.writeGenVenCookieParam = function(e) {
        var t = Nt.GeneralVendors
          , o = Ht.genVendorsConsent
          , n = "";
        t.forEach(function(e) {
            n += e.VendorCustomId + ":" + (o[e.VendorCustomId] ? "1" : "0") + ","
        }),
        Vt.writeCookieParam(e, "genVendors", n)
    }
    ,
    ho.prototype.writeVSConsentCookieParam = function(e) {
        var o = "";
        Ht.vsConsent.forEach(function(e, t) {
            return o += t + ":" + (e ? "1" : "0") + ","
        }),
        o = o.slice(0, -1),
        Vt.writeCookieParam(e, uo, o)
    }
    ,
    ho.prototype.updateGroupsInCookie = function(e, t) {
        void 0 === t && (t = null),
        Vt.writeCookieParam(e, "groups", Bt.arrToStr(t || Ht.groupsConsent))
    }
    ,
    ho.prototype.writeGrpParam = function(e, t) {
        void 0 === t && (t = null),
        this.updateGroupsInCookie(e, t),
        Nt.IsIabEnabled && Qt.isAlertBoxClosedAndValid() && this.insertOrUpdateIabCookies()
    }
    ,
    ho.prototype.insertOrUpdateIabCookies = function() {
        var e = Ht.oneTrustIABConsent;
        if (e.purpose && e.vendors) {
            Ht.isAddtlConsent = Nt.UseGoogleVendors,
            e.IABCookieValue = no.getIABConsentData();
            var t = Nt.ReconsentFrequencyDays;
            Qt.isIABCrossConsentEnabled() ? Qt.setIAB3rdPartyCookie(Ee.EU_CONSENT, e.IABCookieValue, t, !1) : (Vt.setCookie(Ee.EU_PUB_CONSENT, e.IABCookieValue, t),
            Nt.UseGoogleVendors && Vt.setCookie(Ee.ADDITIONAL_CONSENT_STRING, "" + Ht.addtlConsentVersion + Ht.addtlVendors.vendorConsent.join("."), t))
        }
    }
    ,
    ho);
    function ho() {}
    var go, Co = (yo.prototype.initGenVendorConsent = function() {
        var n = this;
        if (Nt.GenVenOptOut) {
            var e = Ot.consentableGrps
              , t = Vt.readCookieParam(Ee.OPTANON_CONSENT, "genVendors");
            t ? (Ht.genVendorsConsent = {},
            t.split(",").forEach(function(e) {
                if (e) {
                    var t = e.split(":");
                    "1" === t[1] && (Ht.genVendorsConsent[t[0]] = !0)
                }
            })) : (Ht.genVendorsConsent = {},
            e.forEach(function(e) {
                var o = Ht.syncRequired ? Xt.checkIfGroupHasConsent(e) : Xt.checkIsActiveByDefault(e);
                e.GeneralVendorsIds && e.GeneralVendorsIds.length && e.GeneralVendorsIds.forEach(function(e) {
                    var t = n.isGenVenPartOfAlwaysActiveGroup(e);
                    Ht.genVendorsConsent[e] = t || o
                })
            }))
        } else
            Ht.genVendorsConsent = {},
            so.writeGenVenCookieParam(Ee.OPTANON_CONSENT)
    }
    ,
    yo.prototype.populateGenVendorLists = function() {
        Ot.consentableGrps.forEach(function(e) {
            e.GeneralVendorsIds && (Xt.isAlwaysActiveGroup(e) ? e.GeneralVendorsIds.forEach(function(e) {
                Ht.alwaysActiveGenVendors.push(e)
            }) : Xt.isOptInGrp(e) ? e.GeneralVendorsIds.forEach(function(e) {
                Ht.optInGenVendors.push(e)
            }) : Xt.isSoftOptInGrp(e) && e.GeneralVendorsIds.forEach(function(e) {
                Ht.optInGenVendors.includes(e) || Ht.softOptInGenVendors.push(e)
            }))
        })
    }
    ,
    yo.prototype.updateGenVendorStatus = function(e, t) {
        Ht.genVendorsConsent[e] = t || this.isGenVenPartOfAlwaysActiveGroup(e)
    }
    ,
    yo.prototype.isGenVenPartOfAlwaysActiveGroup = function(e) {
        return Ht.alwaysActiveGenVendors.includes(e)
    }
    ,
    yo);
    function yo() {}
    var fo, vo = (ko.prototype.synchroniseCookieGroupData = function(e) {
        var t = Vt.readCookieParam(Ee.OPTANON_CONSENT, "groups")
          , a = Bt.strToArr(t)
          , l = Bt.strToArr(t.replace(/:0|:1/g, ""))
          , c = Qt.needReconsent()
          , d = !Qt.isAlertBoxClosedAndValid()
          , u = !1
          , p = !1;
        e.forEach(function(e) {
            var t = e.CustomGroupId
              , o = e.Type === gt || e.Type === mt;
            if (-1 === Bt.indexOf(l, t)) {
                if (o && Nt.IsIabEnabled)
                    return;
                var n;
                n = e.Type === gt ? Mt.isBundleOrStackActive(e, a) : (u = !0,
                Xt.checkIsActiveByDefault(e)),
                p = !0,
                a.push(t + (n ? ":1" : ":0"))
            } else {
                if (Ot.gpcEnabled && e.IsGpcEnabled && (d || c))
                    -1 < (i = a.indexOf(t + ":1")) && (p = !0,
                    a[i] = t + ":0");
                else if (Ot.gpcValueChanged && d) {
                    var r = Xt.checkIsActiveByDefault(e);
                    -1 < (i = a.indexOf(t + ":" + (r ? "0" : "1"))) && (p = !0,
                    a[i] = t + (r ? ":1" : ":0"))
                }
                if (c && "false" === Qt.getIABCrossConsentflagData() && o) {
                    var i, s = Mt.isBundleOrStackActive(e, a);
                    -1 < (i = a.indexOf(t + ":" + (s ? "0" : "1"))) && (p = !0,
                    a[i] = t + (s ? ":1" : ":0"))
                }
            }
        });
        for (var o = a.length, n = function() {
            var t = a[o].replace(/:0|:1/g, "");
            Nt.Groups.some(function(e) {
                return (!c || e.Type !== mt) && (e.CustomGroupId === t || e.SubGroups.some(function(e) {
                    return e.CustomGroupId === t
                }))
            }) || (p = !0,
            a.splice(o, 1))
        }; o--; )
            n();
        p && (Ht.fireOnetrustGrp = !0,
        so.updateGroupsInCookie(Ee.OPTANON_CONSENT, a),
        Ht.syncRequired && u && Vt.removeAlertBox())
    }
    ,
    ko.prototype.groupHasConsent = function(t) {
        var e = Bt.strToArr(Vt.readCookieParam(Ee.OPTANON_CONSENT, "groups"))
          , o = Bt.findIndex(e, function(e) {
            return e.split(":")[0] === t.CustomGroupId
        });
        return -1 < o && "1" === e[o].split(":")[1]
    }
    ,
    ko.prototype.synchroniseCookieHostData = function() {
        var n = this
          , e = Vt.readCookieParam(Ee.OPTANON_CONSENT, "hosts")
          , r = Bt.strToArr(e)
          , i = Bt.strToArr(e.replace(/:0|:1/g, ""))
          , s = !1;
        Nt.Groups.forEach(function(e) {
            y(e.SubGroups, [e]).forEach(function(o) {
                o.Hosts.length && o.Hosts.forEach(function(e) {
                    if (-1 === Bt.indexOf(i, e.HostId)) {
                        s = !0;
                        var t = Ht.syncRequired ? n.groupHasConsent(o) : Xt.checkIsActiveByDefault(o);
                        r.push(e.HostId + (t ? ":1" : ":0"))
                    }
                })
            })
        });
        for (var o = r.length, t = function() {
            var t = r[o].replace(/:0|:1/g, "");
            Nt.Groups.some(function(e) {
                return y(e.SubGroups, [e]).some(function(e) {
                    return e.Hosts.some(function(e) {
                        return e.HostId === t
                    })
                })
            }) || (s = !0,
            r.splice(o, 1))
        }; o--; )
            t();
        s && (Ht.fireOnetrustGrp = !0,
        so.writeHstParam(Ee.OPTANON_CONSENT, r))
    }
    ,
    ko.prototype.toggleGroupHosts = function(e, t) {
        var o = this;
        e.Hosts.forEach(function(e) {
            o.updateHostStatus(e, t)
        })
    }
    ,
    ko.prototype.toggleGroupGenVendors = function(e, t) {
        e.GeneralVendorsIds.forEach(function(e) {
            go.updateGenVendorStatus(e, t)
        })
    }
    ,
    ko.prototype.updateHostStatus = function(t, e) {
        var o = Bt.findIndex(Ht.hostsConsent, function(e) {
            return !t.isActive && t.HostId === e.replace(/:0|:1/g, "")
        });
        if (-1 < o) {
            var n = e || this.isHostPartOfAlwaysActiveGroup(t.HostId);
            Ht.hostsConsent[o] = t.HostId + ":" + (n ? "1" : "0")
        }
    }
    ,
    ko.prototype.isHostPartOfAlwaysActiveGroup = function(e) {
        return Ht.oneTrustAlwaysActiveHosts.includes(e)
    }
    ,
    ko);
    function ko() {}
    var mo, bo = function() {
        this.assets = function() {
            return {
                name: "otCookiePolicy",
                html: '<div class="ot-sdk-cookie-policy ot-sdk-container">\n    <h3 id="cookie-policy-title">Cookie Tracking Table</h3>\n    <div id="cookie-policy-description"></div>\n    <section>\n        <h4 class="ot-sdk-cookie-policy-group">Strictly Necessary Cookies</h4>\n        <p class="ot-sdk-cookie-policy-group-desc">group description</p>\n        <h5 class="cookies-used-header">Cookies Used</h5>\n        <ul class="cookies-list">\n            <li>Cookie 1</li>\n        </ul>\n        <table>\n            <caption class="ot-scrn-rdr">caption</caption>\n            <thead>\n                <tr>\n                    <th scope="col" class="table-header host">Host</th>\n                    <th scope="col" class="table-header host-description">Host Description</th>\n                    <th scope="col" class="table-header cookies">Cookies</th>\n                    <th scope="col" class="table-header life-span">Life Span</th>\n                </tr>\n            </thead>\n            <tbody>\n                <tr>\n                    <td class="host-td" data-label="Host"><span class="ot-mobile-border"></span><a\n                            href="https://cookiepedia.co.uk/host/.app.onetrust.com?_ga=2.157675898.1572084395.1556120090-1266459230.1555593548&_ga=2.157675898.1572084395.1556120090-1266459230.1555593548">Azure</a>\n                    </td>\n                    <td class="host-description-td" data-label="Host Description"><span\n                            class="ot-mobile-border"></span>These\n                        cookies are used to make sure\n                        visitor page requests are routed to the same server in all browsing sessions.</td>\n                    <td class="cookies-td" data-label="Cookies">\n                        <span class="ot-mobile-border"></span>\n                        <ul>\n                            <li>ARRAffinity</li>\n                        </ul>\n                    </td>\n                    <td class="life-span-td" data-label="Life Span"><span class="ot-mobile-border"></span>\n                        <ul>\n                            <li>100 days</li>\n                        </ul>\n                    </td>\n                </tr>\n            </tbody>\n        </table>\n    </section>\n    <section class="subgroup">\n        <h5 class="ot-sdk-cookie-policy-group">Strictly Necessary Cookies</h5>\n        <p class="ot-sdk-cookie-policy-group-desc">description</p>\n        <h6 class="cookies-used-header">Cookies Used</h6>\n        <ul class="cookies-list">\n            <li>Cookie 1</li>\n        </ul>\n        <table>\n            <caption class="ot-scrn-rdr">caption</caption>\n            <thead>\n                <tr>\n                    <th scope="col" class="table-header host">Host</th>\n                    <th scope="col" class="table-header host-description">Host Description</th>\n                    <th scope="col" class="table-header cookies">Cookies</th>\n                    <th scope="col" class="table-header life-span">Life Span</th>\n                </tr>\n            </thead>\n            <tbody>\n                <tr>\n                    <td class="host-td" data-label="Host"><span class="ot-mobile-border"></span><a\n                            href="https://cookiepedia.co.uk/host/.app.onetrust.com?_ga=2.157675898.1572084395.1556120090-1266459230.1555593548&_ga=2.157675898.1572084395.1556120090-1266459230.1555593548">Azure</a>\n                    </td>\n                    <td class="host-description-td" data-label="Host Description">\n                        <span class="ot-mobile-border"></span>\n                        cookies are used to make sureng sessions.\n                    </td>\n                    <td class="cookies-td" data-label="Cookies">\n                        <span class="ot-mobile-border"></span>\n                        <ul>\n                            <li>ARRAffinity</li>\n                        </ul>\n                    </td>\n                    <td class="life-span-td" data-label="Life Span"><span class="ot-mobile-border"></span>\n                        <ul>\n                            <li>100 days</li>\n                        </ul>\n                    </td>\n                </tr>\n            </tbody>\n        </table>\n    </section>\n</div>\n\x3c!-- New Cookies policy Link--\x3e\n<div id="ot-sdk-cookie-policy-v2" class="ot-sdk-cookie-policy ot-sdk-container">\n    <h3 id="cookie-policy-title" class="ot-sdk-cookie-policy-title">Cookie Tracking Table</h3>\n    <div id="cookie-policy-description"></div>\n    <section>\n        <h4 class="ot-sdk-cookie-policy-group">Strictly Necessary Cookies</h4>\n        <p class="ot-sdk-cookie-policy-group-desc">group description</p>\n        <section class="ot-sdk-subgroup">\n            <ul>\n                <li>\n                    <h5 class="ot-sdk-cookie-policy-group">Strictly Necessary Cookies</h5>\n                    <p class="ot-sdk-cookie-policy-group-desc">description</p>\n                </li>\n            </ul>\n        </section>\n        <table>\n            <caption class="ot-scrn-rdr">caption</caption>\n            <thead>\n                <tr>\n                    <th scope="col" class="ot-table-header ot-host">Host</th>\n                    <th scope="col" class="ot-table-header ot-host-description">Host Description</th>\n                    <th scope="col" class="ot-table-header ot-cookies">Cookies</th>\n                    <th scope="col" class="ot-table-header ot-cookies-type">Type</th>\n                    <th scope="col" class="ot-table-header ot-life-span">Life Span</th>\n                </tr>\n            </thead>\n            <tbody>\n                <tr>\n                    <td class="ot-host-td" data-label="Host"><span class="ot-mobile-border"></span><a\n                            href="https://cookiepedia.co.uk/host/.app.onetrust.com?_ga=2.157675898.1572084395.1556120090-1266459230.1555593548&_ga=2.157675898.1572084395.1556120090-1266459230.1555593548">Azure</a>\n                    </td>\n                    <td class="ot-host-description-td" data-label="Host Description">\n                        <span class="ot-mobile-border"></span>\n                        cookies are used to make sureng sessions.\n                    </td>\n                    <td class="ot-cookies-td" data-label="Cookies">\n                        <span class="ot-mobile-border"></span>\n                        <span class="ot-cookies-td-content">ARRAffinity</span>\n                    </td>\n                    <td class="ot-cookies-type" data-label="Type">\n                        <span class="ot-mobile-border"></span>\n                        <span class="ot-cookies-type-td-content">1st Party</span>\n                    </td>\n                    <td class="ot-life-span-td" data-label="Life Span">\n                        <span class="ot-mobile-border"></span>\n                        <span class="ot-life-span-td-content">100 days</span>\n                    </td>\n                </tr>\n            </tbody>\n        </table>\n    </section>\n</div>',
                css: ".ot-sdk-cookie-policy{font-family:inherit;font-size:16px}.ot-sdk-cookie-policy.otRelFont{font-size:1rem}.ot-sdk-cookie-policy h3,.ot-sdk-cookie-policy h4,.ot-sdk-cookie-policy h6,.ot-sdk-cookie-policy p,.ot-sdk-cookie-policy li,.ot-sdk-cookie-policy a,.ot-sdk-cookie-policy th,.ot-sdk-cookie-policy #cookie-policy-description,.ot-sdk-cookie-policy .ot-sdk-cookie-policy-group,.ot-sdk-cookie-policy #cookie-policy-title{color:dimgray}.ot-sdk-cookie-policy #cookie-policy-description{margin-bottom:1em}.ot-sdk-cookie-policy h4{font-size:1.2em}.ot-sdk-cookie-policy h6{font-size:1em;margin-top:2em}.ot-sdk-cookie-policy th{min-width:75px}.ot-sdk-cookie-policy a,.ot-sdk-cookie-policy a:hover{background:#fff}.ot-sdk-cookie-policy thead{background-color:#f6f6f4;font-weight:bold}.ot-sdk-cookie-policy .ot-mobile-border{display:none}.ot-sdk-cookie-policy section{margin-bottom:2em}.ot-sdk-cookie-policy table{border-collapse:inherit}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy{font-family:inherit;font-size:1rem}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy h3,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy h4,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy h6,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy p,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy li,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy a,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy th,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy #cookie-policy-description,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy .ot-sdk-cookie-policy-group,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy #cookie-policy-title{color:dimgray}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy #cookie-policy-description{margin-bottom:1em}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy .ot-sdk-subgroup{margin-left:1.5em}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy #cookie-policy-description,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy .ot-sdk-cookie-policy-group-desc,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy .ot-table-header,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy a,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy span,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy td{font-size:.9em}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy td span,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy td a{font-size:inherit}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy .ot-sdk-cookie-policy-group{font-size:1em;margin-bottom:.6em}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy .ot-sdk-cookie-policy-title{margin-bottom:1.2em}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy>section{margin-bottom:1em}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy th{min-width:75px}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy a,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy a:hover{background:#fff}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy thead{background-color:#f6f6f4;font-weight:bold}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy .ot-mobile-border{display:none}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy section{margin-bottom:2em}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy .ot-sdk-subgroup ul li{list-style:disc;margin-left:1.5em}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy .ot-sdk-subgroup ul li h4{display:inline-block}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy table{border-collapse:inherit;margin:auto;border:1px solid #d7d7d7;border-radius:5px;border-spacing:initial;width:100%;overflow:hidden}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy table th,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy table td{border-bottom:1px solid #d7d7d7;border-right:1px solid #d7d7d7}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy table tr:last-child td{border-bottom:0px}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy table tr th:last-child,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy table tr td:last-child{border-right:0px}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy table .ot-host,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy table .ot-cookies-type{width:25%}.ot-sdk-cookie-policy[dir=rtl]{text-align:left}#ot-sdk-cookie-policy h3{font-size:1.5em}@media only screen and (max-width: 530px){.ot-sdk-cookie-policy:not(#ot-sdk-cookie-policy-v2) table,.ot-sdk-cookie-policy:not(#ot-sdk-cookie-policy-v2) thead,.ot-sdk-cookie-policy:not(#ot-sdk-cookie-policy-v2) tbody,.ot-sdk-cookie-policy:not(#ot-sdk-cookie-policy-v2) th,.ot-sdk-cookie-policy:not(#ot-sdk-cookie-policy-v2) td,.ot-sdk-cookie-policy:not(#ot-sdk-cookie-policy-v2) tr{display:block}.ot-sdk-cookie-policy:not(#ot-sdk-cookie-policy-v2) thead tr{position:absolute;top:-9999px;left:-9999px}.ot-sdk-cookie-policy:not(#ot-sdk-cookie-policy-v2) tr{margin:0 0 1em 0}.ot-sdk-cookie-policy:not(#ot-sdk-cookie-policy-v2) tr:nth-child(odd),.ot-sdk-cookie-policy:not(#ot-sdk-cookie-policy-v2) tr:nth-child(odd) a{background:#f6f6f4}.ot-sdk-cookie-policy:not(#ot-sdk-cookie-policy-v2) td{border:none;border-bottom:1px solid #eee;position:relative;padding-left:50%}.ot-sdk-cookie-policy:not(#ot-sdk-cookie-policy-v2) td:before{position:absolute;height:100%;left:6px;width:40%;padding-right:10px}.ot-sdk-cookie-policy:not(#ot-sdk-cookie-policy-v2) .ot-mobile-border{display:inline-block;background-color:#e4e4e4;position:absolute;height:100%;top:0;left:45%;width:2px}.ot-sdk-cookie-policy:not(#ot-sdk-cookie-policy-v2) td:before{content:attr(data-label);font-weight:bold}.ot-sdk-cookie-policy:not(#ot-sdk-cookie-policy-v2) li{word-break:break-word;word-wrap:break-word}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy table{overflow:hidden}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy table td{border:none;border-bottom:1px solid #d7d7d7}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy table,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy thead,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy tbody,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy th,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy td,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy tr{display:block}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy table .ot-host,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy table .ot-cookies-type{width:auto}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy tr{margin:0 0 1em 0}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy td:before{height:100%;width:40%;padding-right:10px}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy td:before{content:attr(data-label);font-weight:bold}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy li{word-break:break-word;word-wrap:break-word}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy thead tr{position:absolute;top:-9999px;left:-9999px;z-index:-9999}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy table tr:last-child td{border-bottom:1px solid #d7d7d7;border-right:0px}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy table tr:last-child td:last-child{border-bottom:0px}}",
                cssRTL: ".ot-sdk-cookie-policy{font-family:inherit;font-size:16px}.ot-sdk-cookie-policy.otRelFont{font-size:1rem}.ot-sdk-cookie-policy h3,.ot-sdk-cookie-policy h4,.ot-sdk-cookie-policy h6,.ot-sdk-cookie-policy p,.ot-sdk-cookie-policy li,.ot-sdk-cookie-policy a,.ot-sdk-cookie-policy th,.ot-sdk-cookie-policy #cookie-policy-description,.ot-sdk-cookie-policy .ot-sdk-cookie-policy-group,.ot-sdk-cookie-policy #cookie-policy-title{color:dimgray}.ot-sdk-cookie-policy #cookie-policy-description{margin-bottom:1em}.ot-sdk-cookie-policy h4{font-size:1.2em}.ot-sdk-cookie-policy h6{font-size:1em;margin-top:2em}.ot-sdk-cookie-policy th{min-width:75px}.ot-sdk-cookie-policy a,.ot-sdk-cookie-policy a:hover{background:#fff}.ot-sdk-cookie-policy thead{background-color:#f6f6f4;font-weight:bold}.ot-sdk-cookie-policy .ot-mobile-border{display:none}.ot-sdk-cookie-policy section{margin-bottom:2em}.ot-sdk-cookie-policy table{border-collapse:inherit}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy{font-family:inherit;font-size:1rem}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy h3,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy h4,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy h6,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy p,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy li,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy a,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy th,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy #cookie-policy-description,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy .ot-sdk-cookie-policy-group,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy #cookie-policy-title{color:dimgray}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy #cookie-policy-description{margin-bottom:1em}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy .ot-sdk-subgroup{margin-right:1.5em}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy #cookie-policy-description,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy .ot-sdk-cookie-policy-group-desc,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy .ot-table-header,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy a,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy span,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy td{font-size:.9em}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy td span,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy td a{font-size:inherit}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy .ot-sdk-cookie-policy-group{font-size:1em;margin-bottom:.6em}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy .ot-sdk-cookie-policy-title{margin-bottom:1.2em}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy>section{margin-bottom:1em}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy th{min-width:75px}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy a,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy a:hover{background:#fff}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy thead{background-color:#f6f6f4;font-weight:bold}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy .ot-mobile-border{display:none}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy section{margin-bottom:2em}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy .ot-sdk-subgroup ul li{list-style:disc;margin-right:1.5em}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy .ot-sdk-subgroup ul li h4{display:inline-block}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy table{border-collapse:inherit;margin:auto;border:1px solid #d7d7d7;border-radius:5px;border-spacing:initial;width:100%;overflow:hidden}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy table th,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy table td{border-bottom:1px solid #d7d7d7;border-left:1px solid #d7d7d7}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy table tr:last-child td{border-bottom:0px}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy table tr th:last-child,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy table tr td:last-child{border-left:0px}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy table .ot-host,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy table .ot-cookies-type{width:25%}.ot-sdk-cookie-policy[dir=rtl]{text-align:right}#ot-sdk-cookie-policy h3{font-size:1.5em}@media only screen and (max-width: 530px){.ot-sdk-cookie-policy:not(#ot-sdk-cookie-policy-v2) table,.ot-sdk-cookie-policy:not(#ot-sdk-cookie-policy-v2) thead,.ot-sdk-cookie-policy:not(#ot-sdk-cookie-policy-v2) tbody,.ot-sdk-cookie-policy:not(#ot-sdk-cookie-policy-v2) th,.ot-sdk-cookie-policy:not(#ot-sdk-cookie-policy-v2) td,.ot-sdk-cookie-policy:not(#ot-sdk-cookie-policy-v2) tr{display:block}.ot-sdk-cookie-policy:not(#ot-sdk-cookie-policy-v2) thead tr{position:absolute;top:-9999px;right:-9999px}.ot-sdk-cookie-policy:not(#ot-sdk-cookie-policy-v2) tr{margin:0 0 1em 0}.ot-sdk-cookie-policy:not(#ot-sdk-cookie-policy-v2) tr:nth-child(odd),.ot-sdk-cookie-policy:not(#ot-sdk-cookie-policy-v2) tr:nth-child(odd) a{background:#f6f6f4}.ot-sdk-cookie-policy:not(#ot-sdk-cookie-policy-v2) td{border:none;border-bottom:1px solid #eee;position:relative;padding-right:50%}.ot-sdk-cookie-policy:not(#ot-sdk-cookie-policy-v2) td:before{position:absolute;height:100%;right:6px;width:40%;padding-left:10px}.ot-sdk-cookie-policy:not(#ot-sdk-cookie-policy-v2) .ot-mobile-border{display:inline-block;background-color:#e4e4e4;position:absolute;height:100%;top:0;right:45%;width:2px}.ot-sdk-cookie-policy:not(#ot-sdk-cookie-policy-v2) td:before{content:attr(data-label);font-weight:bold}.ot-sdk-cookie-policy:not(#ot-sdk-cookie-policy-v2) li{word-break:break-word;word-wrap:break-word}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy table{overflow:hidden}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy table td{border:none;border-bottom:1px solid #d7d7d7}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy table,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy thead,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy tbody,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy th,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy td,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy tr{display:block}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy table .ot-host,#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy table .ot-cookies-type{width:auto}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy tr{margin:0 0 1em 0}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy td:before{height:100%;width:40%;padding-left:10px}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy td:before{content:attr(data-label);font-weight:bold}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy li{word-break:break-word;word-wrap:break-word}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy thead tr{position:absolute;top:-9999px;right:-9999px;z-index:-9999}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy table tr:last-child td{border-bottom:1px solid #d7d7d7;border-left:0px}#ot-sdk-cookie-policy-v2.ot-sdk-cookie-policy table tr:last-child td:last-child{border-bottom:0px}}"
            }
        }
    }, Po = (So.prototype.isLandingPage = function() {
        var e = Vt.readCookieParam(Ee.OPTANON_CONSENT, "landingPath");
        return !e || e === location.href
    }
    ,
    So.prototype.setLandingPathParam = function(e) {
        Vt.writeCookieParam(Ee.OPTANON_CONSENT, "landingPath", e)
    }
    ,
    So);
    function So() {}
    var Ao, To = "#onetrust-banner-sdk", Io = "#onetrust-pc-sdk", Lo = (_o.prototype.BannerPushDownHandler = function() {
        this.checkIsBrowserIE11OrBelow() || (Ao.pushPageDown(To),
        qt(window).on("resize", function() {
            "none" !== qt(To).css("display") && Ao.pushPageDown(To)
        }))
    }
    ,
    _o.prototype.pushPageUp = function() {
        qt("body").css("top: 0;")
    }
    ,
    _o.prototype.checkIsBrowserIE11OrBelow = function() {
        var e = window.navigator.userAgent;
        return 0 < e.indexOf("MSIE ") || 0 < e.indexOf("Trident/")
    }
    ,
    _o.prototype.pushPageDown = function(e) {
        var t = qt(e).height() + "px";
        qt(e).show().css("\n            bottom: auto;\n            position: absolute;\n            top: -" + t + ";\n        "),
        qt("body").css("\n            position: relative;\n            top: " + t + ";\n        ")
    }
    ,
    _o);
    function _o() {}
    var Vo, Bo = (Eo.prototype.loadBanner = function() {
        It.moduleInitializer.ScriptDynamicLoadEnabled ? "complete" === document.readyState ? qt(window).trigger("otloadbanner") : window.addEventListener("load", function(e) {
            qt(window).trigger("otloadbanner")
        }) : "loading" !== document.readyState ? qt(window).trigger("otloadbanner") : window.addEventListener("DOMContentLoaded", function(e) {
            qt(window).trigger("otloadbanner")
        }),
        Ot.pubDomainData.IsBannerLoaded = !0
    }
    ,
    Eo.prototype.OnConsentChanged = function(e) {
        var t = e.toString();
        Vo.consentChangedEventMap[t] || (Vo.consentChangedEventMap[t] = !0,
        window.addEventListener("consent.onetrust", e))
    }
    ,
    Eo.prototype.triggerGoogleAnalyticsEvent = function(e, t, o, n) {
        var r = !1;
        if (It.moduleInitializer.GATrackToggle && ("AS" === It.moduleInitializer.GATrackAssignedCategory || "" === It.moduleInitializer.GATrackAssignedCategory || window.OnetrustActiveGroups.includes("," + It.moduleInitializer.GATrackAssignedCategory + ",")) && (r = !0),
        !Ot.ignoreGoogleAnlyticsCall && r) {
            void 0 !== window._gaq && window._gaq.push(["_trackEvent", e, t, o, n]),
            "function" == typeof window.ga && window.ga("send", "event", e, t, o, n);
            var i = window[Ot.otDataLayer.name];
            !Ot.otDataLayer.ignore && void 0 !== i && i && i.constructor === Array && i.push({
                event: "trackOptanonEvent",
                optanonCategory: e,
                optanonAction: t,
                optanonLabel: o,
                optanonValue: n
            })
        }
    }
    ,
    Eo.prototype.setAlertBoxClosed = function(e) {
        var t = (new Date).toISOString();
        e ? Vt.setCookie(Ee.ALERT_BOX_CLOSED, t, Nt.ReconsentFrequencyDays) : Vt.setCookie(Ee.ALERT_BOX_CLOSED, t, 0),
        Ot.pagePushedDown && !Ao.checkIsBrowserIE11OrBelow() && Ao.pushPageUp();
        var o = qt(".onetrust-pc-dark-filter").el[0];
        o && "none" !== getComputedStyle(o).getPropertyValue("display") && qt(".onetrust-pc-dark-filter").fadeOut(400)
    }
    ,
    Eo.prototype.updateConsentFromCookie = function(t) {
        return c(this, void 0, void 0, function() {
            return C(this, function(e) {
                return t ? (no.isInitIABCookieData(t) || no.updateFromGlobalConsent(t),
                "init" === t && (Vt.removeIab1(),
                Qt.isAlertBoxClosedAndValid() && Qt.resetTCModel(),
                Vt.removeAlertBox())) : (Qt.resetTCModel(),
                Qt.updateCrossConsentCookie(!1),
                Qt.setIABCookieData()),
                Vo.assetPromise.then(function() {
                    Vo.loadBanner()
                }),
                [2]
            })
        })
    }
    ,
    Eo);
    function Eo() {
        var t = this;
        this.consentChangedEventMap = {},
        this.assetResolve = null,
        this.assetPromise = new Promise(function(e) {
            t.assetResolve = e
        }
        )
    }
    var wo, xo = "opt-out", Go = "OneTrust Cookie Consent", Oo = "Banner Auto Close", No = "Banner Close Button", Do = "Banner - Continue without Accepting", Ho = "Banner - Confirm", Fo = "Preferences Close Button", Ro = "Preference Center Opened From Banner", qo = "Preference Center Opened From Button", Mo = "Preference Center Opened From Function", Uo = "Preferences Save Settings", jo = "Vendors List Opened From Function", zo = "Floating Cookie Settings Open Button", Ko = "Floating Cookie Settings Close Button", Wo = "Preferences Toggle On", Jo = "Preferences Toggle Off", Yo = "General Vendor Toggle On", Xo = "General Vendor Toggle Off", Qo = "Host Toggle On", $o = "Host Toggle Off", Zo = "Preferences Legitimate Interest Objection", en = "Preferences Legitimate Interest Remove Objection", tn = "IAB Vendor Toggle ON", on = "IAB Vendor Toggle Off", nn = "IAB Vendor Legitimate Interest Objection", rn = "IAB Vendor Legitimate Interest Remove Objection", sn = "Vendor Service Toggle On", an = "Vendor Service Toggle Off", ln = (cn.prototype.getDataLanguageCulture = function() {
        var e = Ot.bannerScriptElement;
        return e && e.getAttribute(ze) ? this.checkAndTansformLangCodeWithUnderdscore(e.getAttribute(ze).toLowerCase()) : this.detectDocumentOrBrowserLanguage().toLowerCase()
    }
    ,
    cn.prototype.checkAndTansformLangCodeWithUnderdscore = function(e) {
        return e.replace(/\_/, "-")
    }
    ,
    cn.prototype.detectDocumentOrBrowserLanguage = function() {
        var e = "";
        if (Ot.langSwitcherPldr) {
            var t = Bt.convertKeyValueLowerCase(Ot.langSwitcherPldr)
              , o = this.getUserLanguage().toLowerCase();
            if (!(e = t[o] || t[o + "-" + o] || (t.default === o ? t.default : null)))
                if (2 === o.length)
                    for (var n = 0; n < Object.keys(t).length; n += 1) {
                        var r = Object.keys(t)[n];
                        if (r.substr(0, 2) === o) {
                            e = t[r];
                            break
                        }
                    }
                else
                    2 < o.length && (e = t[o.substr(0, 2)]);
            e = e || t.default
        }
        return e
    }
    ,
    cn.prototype.getUserLanguage = function() {
        return Ot.useDocumentLanguage ? this.checkAndTansformLangCodeWithUnderdscore(document.documentElement.lang) : navigator.languages && navigator.languages.length ? navigator.languages[0] : navigator.language || navigator.userLanguage
    }
    ,
    cn.prototype.isValidLanguage = function(e, t) {
        var o = Bt.convertKeyValueLowerCase(Ot.langSwitcherPldr);
        return !(!o || !o[t] && !o[t + "-" + t] && o.default !== t)
    }
    ,
    cn.prototype.getLangJsonUrl = function(e) {
        void 0 === e && (e = null);
        var t, o = Ot.getRegionRule();
        if (e) {
            if (e = e.toLowerCase(),
            !this.isValidLanguage(o, e))
                return null
        } else
            e = this.getDataLanguageCulture();
        return Ht.lang = e,
        Ht.consentLanguage = e.substr(0, 2),
        t = Ot.canUseConditionalLogic ? Ot.bannerDataParentURL + "/" + o.Id + "/" + Ot.Condition.Id + "/" + e : Ot.bannerDataParentURL + "/" + o.Id + "/" + e,
        Ot.multiVariantTestingEnabled && (t = Ot.bannerDataParentURL + "/" + o.Id + "/variants/" + Ot.selectedVariant.Id + "/" + e),
        t
    }
    ,
    cn.prototype.populateLangSwitcherPlhdr = function() {
        var e = Ot.getRegionRule();
        if (e) {
            var t = e.Variants;
            if (Ot.multiVariantTestingEnabled && t) {
                var o = Vt.getCookie(Ee.SELECTED_VARIANT)
                  , n = void 0;
                o && (n = t[Bt.findIndex(t, function(e) {
                    return e.Id === o
                })]),
                o && n || (n = t[Math.floor(Math.random() * t.length)]),
                Ot.langSwitcherPldr = n.LanguageSwitcherPlaceholder,
                Ot.selectedVariant = n
            } else
                Ot.canUseConditionalLogic ? Ot.langSwitcherPldr = Ot.Condition.LanguageSwitcherPlaceholder : Ot.langSwitcherPldr = e.LanguageSwitcherPlaceholder
        }
    }
    ,
    cn);
    function cn() {}
    var dn, un = (pn.prototype.getLangJson = function(e) {
        void 0 === e && (e = null);
        var t = wo.getLangJsonUrl(e);
        return t ? dn.otFetch(t + ".json") : Promise.resolve(null)
    }
    ,
    pn.prototype.getPersistentCookieSvg = function() {
        var e = Nt.cookiePersistentLogo;
        return e ? dn.otFetch(e, !0) : Promise.resolve(null)
    }
    ,
    pn.prototype.fetchGvlObj = function() {
        return this.otFetch(It.moduleInitializer.IabV2Data.globalVendorListUrl)
    }
    ,
    pn.prototype.fetchGoogleVendors = function() {
        var e = Mt.updateCorrectIABUrl(It.moduleInitializer.GoogleData.googleVendorListUrl);
        return Mt.checkMobileOfflineRequest(Mt.getBannerVersionUrl()) ? Mt.otFetchOfflineFile(Bt.getRelativeURL(e, !0)) : (Ot.mobileOnlineURL.push(e),
        this.otFetch(e))
    }
    ,
    pn.prototype.getStorageDisclosure = function(t) {
        return c(this, void 0, void 0, function() {
            return C(this, function(e) {
                return [2, this.otFetch(t)]
            })
        })
    }
    ,
    pn.prototype.loadCMP = function() {
        var o = this;
        return new Promise(function(e) {
            var t = o.checkIfRequiresPollyfill() ? "otTCF-ie" : "otTCF";
            Mt.jsonp(Mt.getBannerVersionUrl() + "/" + t + ".js", e, e)
        }
        )
    }
    ,
    pn.prototype.getCSBtnContent = function() {
        return c(this, void 0, void 0, function() {
            var t, o, n, r;
            return C(this, function(e) {
                switch (e.label) {
                case 0:
                    return t = Nt.useRTL ? ee.RTL : ee.LTR,
                    Ht.csBtnAsset[t] ? [3, 2] : (o = Mt.getBannerSDKAssestsUrl() + "/" + (Nt.useRTL ? We : Ke),
                    n = Ht.csBtnAsset,
                    r = t,
                    [4, this.otFetch(o)]);
                case 1:
                    n[r] = e.sent(),
                    e.label = 2;
                case 2:
                    return [2, Ht.csBtnAsset[t]]
                }
            })
        })
    }
    ,
    pn.prototype.getPcContent = function(s) {
        return void 0 === s && (s = !1),
        c(this, void 0, void 0, function() {
            var t, o, n, r, i;
            return C(this, function(e) {
                switch (e.label) {
                case 0:
                    return t = Nt.useRTL ? ee.RTL : ee.LTR,
                    Ht.pcAsset[t] && !s ? [3, 2] : (o = Mt.getBannerSDKAssestsUrl(),
                    Nt.PCTemplateUpgrade && (o += "/v2"),
                    n = o + "/" + Ot.pcName + (Nt.useRTL ? "Rtl" : "") + ".json",
                    r = Ht.pcAsset,
                    i = t,
                    [4, this.otFetch(n)]);
                case 1:
                    r[i] = e.sent(),
                    e.label = 2;
                case 2:
                    return [2, Ht.pcAsset[t]]
                }
            })
        })
    }
    ,
    pn.prototype.getBannerContent = function(a, l) {
        return void 0 === a && (a = !1),
        void 0 === l && (l = null),
        c(this, void 0, void 0, function() {
            var t, o, n, r, i, s;
            return C(this, function(e) {
                switch (e.label) {
                case 0:
                    return t = Nt.useRTL ? ee.RTL : ee.LTR,
                    o = l || wo.getDataLanguageCulture(),
                    Ht.bAsset[t] && !a ? [3, 2] : (n = Ot.getRegionRule(),
                    r = void 0,
                    It.fp.CookieV2SSR ? (r = Ot.bannerDataParentURL + "/" + n.Id,
                    Ot.canUseConditionalLogic && (r += "/" + Ot.Condition.Id),
                    r += "/bLayout-" + o + ".json") : r = Mt.getBannerSDKAssestsUrl() + "/" + Ot.bannerName + (Nt.useRTL ? "Rtl" : "") + ".json",
                    i = Ht.bAsset,
                    s = t,
                    [4, this.otFetch(r)]);
                case 1:
                    i[s] = e.sent(),
                    e.label = 2;
                case 2:
                    return [2, Ht.bAsset[t]]
                }
            })
        })
    }
    ,
    pn.prototype.getCommonStyles = function(i) {
        return void 0 === i && (i = !1),
        c(this, void 0, void 0, function() {
            var t, o, n, r;
            return C(this, function(e) {
                switch (e.label) {
                case 0:
                    return t = Nt.useRTL ? ee.RTL : ee.LTR,
                    Ht.cStyles[t] && !i ? [3, 2] : (o = Mt.getBannerSDKAssestsUrl() + "/otCommonStyles" + (Nt.useRTL ? "Rtl" : "") + ".css",
                    n = Ht.cStyles,
                    r = t,
                    [4, this.otFetch(o, !0)]);
                case 1:
                    n[r] = e.sent(),
                    e.label = 2;
                case 2:
                    return [2, Ht.cStyles[t]]
                }
            })
        })
    }
    ,
    pn.prototype.getSyncNtfyContent = function() {
        return c(this, void 0, void 0, function() {
            var t, o, n, r;
            return C(this, function(e) {
                switch (e.label) {
                case 0:
                    return t = Nt.useRTL ? ee.RTL : ee.LTR,
                    Ht.syncNtfyContent[t] ? [3, 2] : (o = Mt.getBannerSDKAssestsUrl() + "/otSyncNotification" + (Nt.useRTL ? "Rtl" : "") + ".json",
                    n = Ht.syncNtfyContent,
                    r = t,
                    [4, this.otFetch(o)]);
                case 1:
                    n[r] = e.sent(),
                    e.label = 2;
                case 2:
                    return [2, Ht.syncNtfyContent[t]]
                }
            })
        })
    }
    ,
    pn.prototype.getConsentProfile = function(e, t) {
        var o = this
          , n = {
            Identifier: e,
            TenantId: Ht.tenantId,
            Authorization: t
        };
        return new Promise(function(e) {
            o.getJSON(Ht.consentApi, n, e, e)
        }
        )
    }
    ,
    pn.prototype.checkIfRequiresPollyfill = function() {
        var e = window.navigator.userAgent;
        return 0 < e.indexOf("MSIE ") || 0 < e.indexOf("Trident/") || "undefined" == typeof Set
    }
    ,
    pn.prototype.otFetch = function(r, i) {
        return void 0 === i && (i = !1),
        c(this, void 0, void 0, function() {
            var t, o, n = this;
            return C(this, function(e) {
                switch (e.label) {
                case 0:
                    return Mt.checkMobileOfflineRequest(r) ? [4, Mt.otFetchOfflineFile(r)] : [3, 2];
                case 1:
                    return [2, e.sent()];
                case 2:
                    return e.trys.push([2, 9, , 10]),
                    Ot.mobileOnlineURL.push(r),
                    "undefined" != typeof fetch ? [3, 3] : [2, new Promise(function(e) {
                        n.getJSON(r, null, e, e, i)
                    }
                    )];
                case 3:
                    return [4, fetch(r)];
                case 4:
                    return t = e.sent(),
                    i ? [4, t.text()] : [3, 6];
                case 5:
                    return [2, e.sent()];
                case 6:
                    return [4, t.json()];
                case 7:
                    return [2, e.sent()];
                case 8:
                    return [3, 10];
                case 9:
                    return o = e.sent(),
                    console.log("Error in fetch URL : " + r + " Exception :" + o),
                    [3, 10];
                case 10:
                    return [2]
                }
            })
        })
    }
    ,
    pn.prototype.getJSON = function(e, t, o, n, r) {
        void 0 === t && (t = null),
        void 0 === r && (r = !1);
        var i = new XMLHttpRequest;
        if (i.open("GET", e, !0),
        t)
            for (var s in t)
                i.setRequestHeader(s, t[s]);
        i.onload = function() {
            if (200 <= this.status && this.status < 400 && this.responseText) {
                var e = void 0;
                e = r ? this.responseText : JSON.parse(this.responseText),
                o(e)
            } else
                n({
                    message: "Error Loading Data",
                    statusCode: this.status
                })
        }
        ,
        i.onerror = function(e) {
            n(e)
        }
        ,
        i.send()
    }
    ,
    pn);
    function pn() {}
    var hn, gn = (new bo).assets(), Cn = (yn.prototype.initializeFeaturesAndSpecialPurposes = function() {
        Ht.oneTrustIABConsent.features = [],
        Ht.oneTrustIABConsent.specialPurposes = [],
        Nt.Groups.forEach(function(e) {
            if ("IAB2_FEATURE" === e.Type || "IAB2_SPL_PURPOSE" === e.Type) {
                var t = {};
                t.groupId = e.OptanonGroupId,
                t.purposeId = e.PurposeId,
                t.value = !0,
                "IAB2_FEATURE" === e.Type ? Ht.oneTrustIABConsent.features.push(t) : Ht.oneTrustIABConsent.specialPurposes.push(t)
            }
        })
    }
    ,
    yn.prototype.initGrpsAndHosts = function() {
        this.initializeGroupData(Ot.consentableGrps),
        Nt.showCookieList && Mt.isOptOutEnabled() ? this.initializeHostData(Ot.consentableGrps) : (Ht.hostsConsent = [],
        so.writeHstParam(Ee.OPTANON_CONSENT))
    }
    ,
    yn.prototype.ensureHtmlGroupDataInitialised = function() {
        if (this.initGrpsAndHosts(),
        Ht.showGeneralVendors && (go.populateGenVendorLists(),
        go.initGenVendorConsent()),
        Nt.IsIabEnabled && (this.initializeIABData(),
        this.initializeFeaturesAndSpecialPurposes()),
        Ht.vsIsActiveAndOptOut && this.initializeVendorsService(),
        Qt.setOrUpdate3rdPartyIABConsentFlag(),
        Qt.setGeolocationInCookies(),
        Nt.IsConsentLoggingEnabled) {
            var e = window.OneTrust.dataSubjectParams || {}
              , t = Vt.readCookieParam(Ee.OPTANON_CONSENT, "iType")
              , o = ""
              , n = !1;
            t && Ht.isV2Stub && e.id && e.token && (n = !0,
            o = U[t]),
            eo.createConsentTxn(!1, o, !1, n)
        }
    }
    ,
    yn.prototype.initializeVendorsService = function() {
        var n = Qt.isAlertBoxClosedAndValid()
          , e = Vt.readCookieParam(Ee.OPTANON_CONSENT, uo)
          , r = Bt.strToMap(e);
        Ht.getVendorsInDomain().forEach(function(e, t) {
            if (!r.has(t)) {
                var o = !n && Xt.checkIsActiveByDefault(e.groupRef);
                r.set(t, o)
            }
        }),
        Ht.vsConsent = r
    }
    ,
    yn.prototype.initializeGroupData = function(e) {
        var t = Vt.readCookieParam(Ee.OPTANON_CONSENT, ao);
        t ? (fo.synchroniseCookieGroupData(e),
        t = Vt.readCookieParam(Ee.OPTANON_CONSENT, ao),
        Ht.groupsConsent = Bt.strToArr(t)) : (Ht.groupsConsent = [],
        e.forEach(function(e) {
            Ht.groupsConsent.push(e.CustomGroupId + (Xt.checkIsActiveByDefault(e) && e.HasConsentOptOut ? ":1" : ":0"))
        }),
        Nt.IsConsentLoggingEnabled && window.addEventListener("beforeunload", this.consentDefaulCall))
    }
    ,
    yn.prototype.initializeHostData = function(e) {
        var t = Vt.readCookieParam(Ee.OPTANON_CONSENT, "hosts");
        if (t)
            fo.synchroniseCookieHostData(),
            t = Vt.readCookieParam(Ee.OPTANON_CONSENT, "hosts"),
            Ht.hostsConsent = Bt.strToArr(t),
            e.forEach(function(e) {
                Xt.isAlwaysActiveGroup(e) && e.Hosts.length && e.Hosts.forEach(function(e) {
                    Ht.oneTrustAlwaysActiveHosts.push(e.HostId)
                })
            });
        else {
            Ht.hostsConsent = [];
            var r = {};
            e.forEach(function(e) {
                var o = Xt.isAlwaysActiveGroup(e)
                  , n = Ht.syncRequired ? fo.groupHasConsent(e) : Xt.checkIsActiveByDefault(e);
                e.Hosts.length && e.Hosts.forEach(function(e) {
                    if (r[e.HostId])
                        fo.updateHostStatus(e, n);
                    else {
                        r[e.HostId] = !0,
                        o && Ht.oneTrustAlwaysActiveHosts.push(e.HostId);
                        var t = fo.isHostPartOfAlwaysActiveGroup(e.HostId);
                        Ht.hostsConsent.push(e.HostId + (t || n ? ":1" : ":0"))
                    }
                })
            })
        }
    }
    ,
    yn.prototype.consentDefaulCall = function() {
        var e = parseInt(Vt.readCookieParam(Ee.OPTANON_CONSENT, Le), 10);
        !isNaN(e) && 0 !== e || (Vo.triggerGoogleAnalyticsEvent(Go, "Click", "No interaction"),
        Nt.IsConsentLoggingEnabled && eo.createConsentTxn(!0),
        window.removeEventListener("beforeunload", hn.consentDefaulCall))
    }
    ,
    yn.prototype.fetchAssets = function(g) {
        return void 0 === g && (g = null),
        c(this, void 0, void 0, function() {
            var t, o, n, r, i, s, a, l, c, d, u, p, h;
            return C(this, function(e) {
                switch (e.label) {
                case 0:
                    return i = It.moduleInitializer,
                    s = Qt.isAlertBoxClosedAndValid(),
                    a = !!g,
                    l = !i.IsSuppressBanner || Nt.ShowAlertNotice && !s && i.IsSuppressBanner && !qt("#onetrust-banner-sdk").length,
                    c = qt("#ot-sdk-btn").length || qt(".ot-sdk-show-settings").length || qt(".optanon-show-settings").length,
                    d = "IAB2" === Nt.IabType ? !i.TenantFeatures.CookieV2RemoveSettingsIcon && !c : Nt.PCShowPersistentCookiesHoverButton,
                    u = "true" === Ht.urlParams.get(at),
                    Ht.hideBanner = u,
                    [4, Promise.all([!l || Nt.NoBanner || u ? Promise.resolve(null) : dn.getBannerContent(a, g), !i.IsSuppressPC || Ht.isPCVisible ? dn.getPcContent() : Promise.resolve(null), d ? dn.getCSBtnContent() : Promise.resolve(null), dn.getCommonStyles()])];
                case 1:
                    return h = e.sent(),
                    t = h[0],
                    o = h[1],
                    n = h[2],
                    r = h[3],
                    t && (p = t.html,
                    It.fp.CookieV2SSR || (p = atob(t.html)),
                    this.bannerGroup = {
                        name: t.name,
                        html: p,
                        css: t.css
                    }),
                    o && (this.preferenceCenterGroup = {
                        name: o.name,
                        html: atob(o.html),
                        css: o.css
                    },
                    It.isV2Template = Nt.PCTemplateUpgrade && /otPcPanel|otPcCenter|otPcTab/.test(o.name)),
                    r && (this.commonStyles = r),
                    this.cookieListGroup = {
                        name: gn.name,
                        html: gn.html,
                        css: Nt.useRTL ? gn.cssRTL : gn.css
                    },
                    n && (this.csBtnGroup = {
                        name: "CookieSettingsButton",
                        html: atob(n.html),
                        css: n.css
                    }),
                    [2]
                }
            })
        })
    }
    ,
    yn.prototype.initializeIabPurposeConsentOnReload = function() {
        var t = this;
        Ot.consentableIabGrps.forEach(function(e) {
            t.setIABConsent(e, !1),
            e.IsLegIntToggle = !0,
            t.setIABConsent(e, !1)
        })
    }
    ,
    yn.prototype.initializeIABData = function(o, n) {
        var r = this;
        void 0 === o && (o = !1),
        void 0 === n && (n = !1);
        var e = Ht.oneTrustIABConsent;
        if (e.purpose = [],
        e.vendors = [],
        e.legIntVendors = [],
        e.specialFeatures = [],
        e.legimateInterest = [],
        Ht.addtlVendors.vendorConsent = [],
        !e.IABCookieValue || o || n || Qt.reconsentRequired()) {
            Ot.consentableIabGrps.forEach(function(e) {
                if (n)
                    r.setIABConsent(e, Xt.isAlwaysActiveGroup(e));
                else {
                    var t = o && e.HasConsentOptOut;
                    r.setIABConsent(e, t),
                    "IAB2_PURPOSE" === e.Type && (e.IsLegIntToggle = !0,
                    r.setIABConsent(e, e.HasLegIntOptOut))
                }
            });
            var t = o || !n && Nt.VendorConsentModel === xo;
            Qt.setIABVendor(t),
            !Qt.reconsentRequired() || o || n || Qt.resetTCModel()
        } else
            this.initializeIabPurposeConsentOnReload(),
            no.populateGoogleConsent(),
            no.populateVendorAndPurposeFromCookieData()
    }
    ,
    yn.prototype.canSoftOptInInsertForGroup = function(e) {
        var t = Xt.getGroupById(e);
        if (t) {
            var o = t && !t.Parent ? t : Xt.getParentGroup(t.Parent);
            return "inactive landingpage" !== Xt.getGrpStatus(o).toLowerCase() || !mo.isLandingPage()
        }
    }
    ,
    yn.prototype.setIABConsent = function(e, t) {
        e.Type === vt ? this.setIabSpeciFeatureConsent(e, t) : e.IsLegIntToggle ? (this.setIabLegIntConsent(e, t),
        e.IsLegIntToggle = !1) : this.setIabPurposeConsent(e, t)
    }
    ,
    yn.prototype.setIabPurposeConsent = function(o, n) {
        var r = !1;
        Ht.oneTrustIABConsent.purpose = Ht.oneTrustIABConsent.purpose.map(function(e) {
            var t = e.split(":")[0];
            return t === o.IabGrpId && (e = t + ":" + n,
            r = !0),
            e
        }),
        r || Ht.oneTrustIABConsent.purpose.push(o.IabGrpId + ":" + n)
    }
    ,
    yn.prototype.setIabLegIntConsent = function(o, n) {
        var r = !1;
        Ht.oneTrustIABConsent.legimateInterest = Ht.oneTrustIABConsent.legimateInterest.map(function(e) {
            var t = e.split(":")[0];
            return t === o.IabGrpId && (e = t + ":" + n,
            r = !0),
            e
        }),
        r || Ht.oneTrustIABConsent.legimateInterest.push(o.IabGrpId + ":" + n)
    }
    ,
    yn.prototype.setIabSpeciFeatureConsent = function(o, n) {
        var r = !1;
        Ht.oneTrustIABConsent.specialFeatures = Ht.oneTrustIABConsent.specialFeatures.map(function(e) {
            var t = e.split(":")[0];
            return t === o.IabGrpId && (e = t + ":" + n,
            r = !0),
            e
        }),
        r || Ht.oneTrustIABConsent.specialFeatures.push(o.IabGrpId + ":" + n)
    }
    ,
    yn);
    function yn() {}
    var fn, vn = (kn.prototype.getAllowAllButton = function() {
        return qt("#onetrust-pc-sdk #accept-recommended-btn-handler")
    }
    ,
    kn.prototype.getSelectedVendors = function() {
        return qt("#onetrust-pc-sdk " + Kt.P_Tgl_Cntr + " .ot-checkbox input:checked")
    }
    ,
    kn);
    function kn() {}
    var mn, bn = (Pn.prototype.setBannerFocus = function() {
        var e = Array.prototype.slice.call(qt("#onetrust-banner-sdk .onetrust-vendors-list-handler").el)
          , t = Array.prototype.slice.call(qt('#onetrust-banner-sdk #onetrust-policy-text [href],#onetrust-banner-sdk #onetrust-policy-text button,#onetrust-banner-sdk #onetrust-policy-text [tabindex]:not([tabindex="-1"])').el)
          , o = Array.prototype.slice.call(qt("#onetrust-banner-sdk .ot-bnr-save-handler").el)
          , n = Array.prototype.slice.call(qt("#onetrust-banner-sdk #onetrust-pc-btn-handler").el)
          , r = Array.prototype.concat.call(Array.prototype.slice.call(qt("#onetrust-banner-sdk .category-switch-handler:not([disabled])").el), Array.prototype.slice.call(qt("#onetrust-banner-sdk .ot-cat-lst button").el), e)
          , i = Array.prototype.concat.call(t, r)
          , s = Array.prototype.slice.call(qt("#onetrust-banner-sdk .onetrust-close-btn-handler").el);
        Ot.bannerName === Qe && (i = Array.prototype.concat.call(e, t));
        var a = Array.prototype.slice.call(qt("#onetrust-banner-sdk #onetrust-accept-btn-handler").el)
          , l = Array.prototype.slice.call(qt("#onetrust-banner-sdk #onetrust-reject-all-handler").el)
          , c = Array.prototype.concat.call(o, a, l, n);
        (Ot.bannerName !== Ye || Nt.IsIabEnabled) && Ot.bannerName !== Je && Ot.bannerName !== Ze || (c = Array.prototype.concat.call(n, l, a));
        var d = Array.prototype.slice.call(qt("#onetrust-banner-sdk .ot-gv-list-handler").el);
        Ot.bannerName === et ? (i = Array.prototype.concat.call(d, i),
        c = Array.prototype.slice.call(qt("#onetrust-banner-sdk #onetrust-button-group button").el)) : i = Array.prototype.concat.call(i, d),
        this.bannerEl = Array.prototype.concat.call(Array.prototype.slice.call(qt("#onetrust-banner-sdk #onetrust-cookie-btn").el), i, Array.prototype.slice.call(qt("#onetrust-banner-sdk .banner-option-input").el), c, Array.prototype.slice.call(qt("#onetrust-banner-sdk .ot-bnr-footer-logo a").el), s),
        this.banner = qt("#onetrust-banner-sdk").el[0],
        (Nt.BInitialFocus || Nt.BInitialFocusLinkAndButton || Nt.ForceConsent) && (Nt.BInitialFocus ? this.banner.focus() : this.bannerEl[0].focus())
    }
    ,
    Pn.prototype.handleBannerFocus = function(e, t) {
        var o = e.target
          , n = mn.bannerEl
          , r = n.indexOf(o)
          , i = n.length - 1
          , s = null;
        if (!Nt.ForceConsent && (Nt.BInitialFocus || Nt.BInitialFocusLinkAndButton) && (t && 0 === r || !t && r === i))
            Mt.resetFocusToBody();
        else if (this.banner === o)
            t && Nt.ForceConsent ? s = n[i] : t || (s = n[0]);
        else
            for (; !s; ) {
                var a = void 0;
                0 !== (a = t ? 0 === r ? n[i] : n[r - 1] : r === i ? n[0] : n[r + 1]).clientHeight || 0 !== a.offsetHeight ? s = a : t ? r-- : r++
            }
        s && (e.preventDefault(),
        s.focus())
    }
    ,
    Pn.prototype.setPCFocus = function(e) {
        if (e && !(e.length <= 0)) {
            for (var t = 0; t < e.length; t++)
                e[t].setAttribute("tabindex", "0");
            this.setFirstAndLast(e);
            var o = Nt.ShowPreferenceCenterCloseButton
              , n = o ? this.getElementForFocus(e, Nt.PCLayout.Popup ? 2 : 1, !0) : null
              , r = {
                preventScroll: !0
            };
            this.firstItem ? o ? n.focus(r) : this.firstItem.focus(r) : e[0].focus(),
            this.firstItem && qt(this.firstItem).on("keydown", mn.firstItemHandler),
            this.lastItem && qt(this.lastItem).on("keydown", mn.lastItemHandler)
        }
    }
    ,
    Pn.prototype.setFirstAndLast = function(e) {
        this.firstItem = this.getElementForFocus(e, 0, !0),
        this.lastItem = this.firstItem ? this.getElementForFocus(e, e.length - 1, !1) : null
    }
    ,
    Pn.prototype.setLastItem = function() {
        var e = this.getPCElements()
          , t = this.getElementForFocus(e, e.length - 1, !1);
        t !== this.lastItem && (qt(this.lastItem).off("keydown", mn.lastItemHandler),
        this.lastItem = t,
        qt(t).on("keydown", mn.lastItemHandler))
    }
    ,
    Pn.prototype.getPCElements = function() {
        var e = "#onetrust-pc-sdk #close-pc-btn-handler,\n            #onetrust-pc-sdk .back-btn-handler,\n            #onetrust-pc-sdk ." + Kt.P_Active_Menu + ',\n            #onetrust-pc-sdk input,\n            #onetrust-pc-sdk a,\n            #onetrust-pc-sdk [tabindex="0"] button,\n            #onetrust-pc-sdk .save-preference-btn-handler,\n            #onetrust-pc-sdk .ot-pc-refuse-all-handler,\n            #onetrust-pc-sdk #accept-recommended-btn-handler';
        return Ht.pcLayer === _.CookieList ? e += " ,#onetrust-pc-sdk " + Kt.P_Content + " .powered-by-logo" : e += ",#onetrust-pc-sdk #vendor-list-save-btn .powered-by-logo",
        Array.prototype.slice.call(qt(e).el)
    }
    ,
    Pn.prototype.getActiveTab = function() {
        return document.querySelector('#onetrust-pc-sdk .category-menu-switch-handler[tabindex="0"]')
    }
    ,
    Pn.prototype.getElementForFocus = function(e, t, o) {
        for (var n = e[t]; o ? n && null === n.offsetParent && t < e.length - 1 : n && null === n.offsetParent && 0 < t; )
            n = e[t],
            o ? ++t : --t;
        return n
    }
    ,
    Pn.prototype.firstItemHandler = function(e) {
        var t = document.getElementById("onetrust-banner-sdk");
        if (9 === e.keyCode && e.shiftKey && mn.firstItem !== t)
            e.preventDefault(),
            mn.lastItem.focus();
        else {
            var o = "close-pc-btn-handler" === e.target.id && ("13" === e.keyCode || "32" === e.keyCode || "Enter" === e.code || "Space" === e.code);
            if (Nt.PCLayout.Tab && Ht.pcLayer === _.PrefCenterHome && !o) {
                var n = mn.getActiveTab();
                n && (e.preventDefault(),
                n.focus())
            }
        }
    }
    ,
    Pn.prototype.lastItemHandler = function(e) {
        if (9 === e.keyCode && !e.shiftKey) {
            e.preventDefault();
            var t = Ht.pcLayer === _.VendorList || Ht.pcLayer === _.CookieList;
            Nt.PCLayout.Tab && Ht.isPCVisible && !Nt.ShowPreferenceCenterCloseButton && !t ? mn.getActiveTab().focus() : mn.firstItem.focus()
        }
    }
    ,
    Pn);
    function Pn() {
        this.bannerEl = []
    }
    var Sn, An = (Tn.prototype.getAllGroupElements = function() {
        return document.querySelectorAll("div#onetrust-pc-sdk " + Kt.P_Category_Grp + " " + Kt.P_Category_Item + ":not(.ot-vnd-item)")
    }
    ,
    Tn.prototype.toggleGrpElements = function(e, t, o) {
        Ot.pcName === st && Nt.PCTemplateUpgrade && (e = document.querySelector("#ot-desc-id-" + e.getAttribute("data-optanongroupid")));
        for (var n = e.querySelectorAll('input[class*="category-switch-handler"]'), r = 0; r < n.length; r++)
            Bt.setCheckedAttribute(null, n[r], o),
            n[r] && Nt.PCShowConsentLabels && (n[r].parentElement.parentElement.querySelector(".ot-label-status").innerHTML = o ? Nt.PCActiveText : Nt.PCInactiveText);
        Ot.legIntSettings.PAllowLI && Ot.legIntSettings.PShowLegIntBtn && t.Type === ft && t.HasLegIntOptOut && Sn.updateLegIntBtnElement(e.querySelector(".ot-leg-btn-container"), o)
    }
    ,
    Tn.prototype.toogleAllSubGrpElements = function(e, t) {
        if (e.ShowSubgroup) {
            var o = e.CustomGroupId
              , n = this.getGroupElementByOptanonGroupId(o.toString());
            Sn.toogleSubGroupElement(n, t, e.IsLegIntToggle)
        } else
            this.updateHiddenSubGroupData(e, t)
    }
    ,
    Tn.prototype.toogleSubGroupElement = function(e, t, o, n) {
        void 0 === o && (o = !1),
        void 0 === n && (n = !1),
        Ot.pcName === st && Nt.PCTemplateUpgrade && (e = document.querySelector("#ot-desc-id-" + e.getAttribute("data-optanongroupid")));
        for (var r = e.querySelectorAll("li" + Kt.P_Subgrp_li), i = 0; i < r.length; i++) {
            var s = Xt.getGroupById(r[i].getAttribute("data-optanongroupid"))
              , a = s.OptanonGroupId
              , l = Xt.getParentGroup(s.Parent);
            Ot.legIntSettings.PAllowLI && Ot.legIntSettings.PShowLegIntBtn && o && s.Type === ft && s.HasLegIntOptOut && l.ShowSubgroupToggle && Sn.updateLegIntBtnElement(r[i], t);
            var c = o ? "[id='ot-sub-group-id-" + a + "-leg-out']" : "[id='ot-sub-group-id-" + a + "']"
              , d = r[i].querySelector('input[class*="cookie-subgroup-handler"]' + c);
            Bt.setCheckedAttribute(null, d, t),
            d && Nt.PCShowConsentLabels && (d.parentElement.parentElement.querySelector(".ot-label-status").innerHTML = t ? Nt.PCActiveText : Nt.PCInactiveText),
            n || (s.IsLegIntToggle = o,
            Sn.toggleGrpStatus(s, t),
            s.IsLegIntToggle = !1,
            fo.toggleGroupHosts(s, t),
            Ht.genVenOptOutEnabled && fo.toggleGroupGenVendors(s, t))
        }
    }
    ,
    Tn.prototype.toggleGrpStatus = function(e, t) {
        var o = e.IsLegIntToggle && e.Type === ft ? t ? en : Zo : t ? Wo : Jo;
        Vo.triggerGoogleAnalyticsEvent(Go, o, e.GroupName + ": " + e.OptanonGroupId),
        t ? this.updateEnabledGroupData(e) : this.updateDisabledGroupData(e)
    }
    ,
    Tn.prototype.setInputID = function(e, t, o, n, r) {
        qt(e).attr("id", t),
        qt(e).attr("name", t),
        qt(e).data("optanonGroupId", o),
        Bt.setCheckedAttribute(null, e, n),
        qt(e).attr("aria-labelledby", r)
    }
    ,
    Tn.prototype.updateEnabledGroupData = function(e) {
        if (-1 < St.indexOf(e.Type))
            this.updateIabGroupData(e, !0);
        else {
            var t = Sn.getGroupVariable()
              , o = Bt.indexOf(t, e.CustomGroupId + ":0");
            -1 !== o && (t[o] = e.CustomGroupId + ":1")
        }
    }
    ,
    Tn.prototype.updateDisabledGroupData = function(e) {
        if (-1 < St.indexOf(e.Type))
            this.updateIabGroupData(e, !1);
        else if (e.Status !== De) {
            var t = Sn.getGroupVariable()
              , o = Bt.indexOf(t, e.CustomGroupId + ":1");
            -1 !== o && (t[o] = e.CustomGroupId + ":0")
        }
    }
    ,
    Tn.prototype.updateIabGroupData = function(e, t) {
        if (e.Type === vt)
            this.updateIabSpecialFeatureData(e.IabGrpId, t);
        else {
            var o = e.IsLegIntToggle ? Ht.vendors.selectedLegInt : Ht.vendors.selectedPurpose;
            this.updateIabPurposeData(e.IabGrpId, t, o)
        }
    }
    ,
    Tn.prototype.isAllSubgroupsDisabled = function(e) {
        return !e.SubGroups.some(function(e) {
            return Sn.isGroupActive(e)
        })
    }
    ,
    Tn.prototype.isAllSubgroupsEnabled = function(e) {
        return !e.SubGroups.some(function(e) {
            return Sn.IsGroupInActive(e)
        })
    }
    ,
    Tn.prototype.toggleGroupHtmlElement = function(e, t, o) {
        if (Ot.legIntSettings.PAllowLI && Ot.legIntSettings.PShowLegIntBtn && e.Type === ft && e.HasLegIntOptOut) {
            var n = document.querySelector("[data-el-id=" + t + "]");
            n && this.updateLegIntBtnElement(n, o)
        }
        var r = qt("#ot-group-id-" + t).el[0];
        Bt.setCheckedAttribute(null, r, o),
        r && Nt.PCShowConsentLabels && (r.parentElement.querySelector(".ot-label-status").innerHTML = o ? Nt.PCActiveText : Nt.PCInactiveText)
    }
    ,
    Tn.prototype.updateLegIntBtnElement = function(e, t) {
        var o = Ot.legIntSettings
          , n = e.querySelector(".ot-obj-leg-btn-handler")
          , r = e.querySelector(".ot-remove-objection-handler");
        t ? (n.classList.add("ot-inactive-leg-btn"),
        n.classList.add("ot-leg-int-enabled"),
        n.classList.remove("ot-active-leg-btn")) : (n.classList.add("ot-active-leg-btn"),
        n.classList.remove("ot-inactive-leg-btn"),
        n.classList.remove("ot-leg-int-enabled")),
        n.querySelector("span").innerText = t ? o.PObjectLegIntText : o.PObjectionAppliedText,
        Lt(r, "display: " + (t ? "none" : "inline-block") + ";", !0)
    }
    ,
    Tn.prototype.isGroupActive = function(e) {
        return -1 < St.indexOf(e.Type) ? -1 !== this.isIabPurposeActive(e) : -1 !== Ft.inArray(e.CustomGroupId + ":1", Sn.getGroupVariable())
    }
    ,
    Tn.prototype.safeFormattedGroupDescription = function(e) {
        return e && e.GroupDescription ? e.GroupDescription.replace(/\r\n/g, "<br>") : ""
    }
    ,
    Tn.prototype.canInsertForGroup = function(e, t) {
        void 0 === t && (t = !1);
        var o, n = null != e && void 0 !== e, r = Vt.readCookieParam(Ee.OPTANON_CONSENT, "groups"), i = Ht.groupsConsent.join(","), s = Vt.readCookieParam(Ee.OPTANON_CONSENT, "hosts"), a = Ht.hostsConsent.join(",");
        if (t)
            return !0;
        r === i && s === a || hn.ensureHtmlGroupDataInitialised();
        var l = [];
        if (Ht.showGeneralVendors)
            for (var c = 0, d = Object.entries(Ht.genVendorsConsent); c < d.length; c++) {
                var u = d[c]
                  , p = u[0]
                  , h = u[1];
                l.push(p + ":" + (h ? "1" : "0"))
            }
        Ht.showVendorService && Ht.vsConsent.forEach(function(e, t) {
            l.push(t + ":" + (e ? "1" : "0"))
        });
        var g = Ht.groupsConsent.concat(Ht.hostsConsent).concat(l);
        o = Bt.contains(g, e + ":1");
        var C = this.doesHostExist(e)
          , y = this.doesGroupExist(e)
          , f = !1;
        Ht.showGeneralVendors ? f = this.doesGenVendorExist(e) : Ht.showVendorService && (f = this.doesVendorServiceExist(e));
        var v = !(!C && !f) || o && hn.canSoftOptInInsertForGroup(e);
        return !(!n || !(o && v || !y && !C && !f))
    }
    ,
    Tn.prototype.setAllowAllButton = function() {
        var t = 0
          , e = Nt.Groups.some(function(e) {
            if (-1 === At.indexOf(e.Type))
                return Sn.IsGroupInActive(e) && t++,
                e.SubGroups.some(function(e) {
                    return Sn.IsGroupInActive(e)
                }) && t++,
                1 <= t
        })
          , o = fn.getAllowAllButton();
        return e ? o.show("inline-block") : o.hide(),
        mn.lastItem && mn.setLastItem(),
        e
    }
    ,
    Tn.prototype.getGroupVariable = function() {
        return Ht.groupsConsent
    }
    ,
    Tn.prototype.IsGroupInActive = function(e) {
        return -1 < St.indexOf(e.Type) ? -1 === this.isIabPurposeActive(e) : !(-1 < At.indexOf(e.Type)) && -1 === Ft.inArray(e.CustomGroupId + ":1", Sn.getGroupVariable())
    }
    ,
    Tn.prototype.updateIabPurposeData = function(t, e, o) {
        var n = Bt.findIndex(o, function(e) {
            return e.split(":")[0] === t
        });
        o[n = -1 === n ? Number(t) : n] = t + ":" + e
    }
    ,
    Tn.prototype.updateIabSpecialFeatureData = function(t, e) {
        var o = Bt.findIndex(Ht.vendors.selectedSpecialFeatures, function(e) {
            return e.split(":")[0] === t
        });
        o = -1 === o ? Number(t) : o,
        Ht.vendors.selectedSpecialFeatures[o] = t + ":" + e
    }
    ,
    Tn.prototype.getGroupElementByOptanonGroupId = function(e) {
        return document.querySelector("#onetrust-pc-sdk " + Kt.P_Category_Grp + " " + Kt.P_Category_Item + '[data-optanongroupid=\n            "' + e + '"]')
    }
    ,
    Tn.prototype.updateHiddenSubGroupData = function(e, t) {
        e.SubGroups.forEach(function(e) {
            Sn.toggleGrpStatus(e, t),
            fo.toggleGroupHosts(e, t),
            Ht.genVenOptOutEnabled && fo.toggleGroupGenVendors(e, t)
        })
    }
    ,
    Tn.prototype.isIabPurposeActive = function(e) {
        var t;
        return t = e.Type === vt ? Ht.vendors.selectedSpecialFeatures : e.IsLegIntToggle ? Ht.vendors.selectedLegInt : Ht.vendors.selectedPurpose,
        Ft.inArray(e.IabGrpId + ":true", t)
    }
    ,
    Tn.prototype.doesGroupExist = function(e) {
        return !!Xt.getGroupById(e)
    }
    ,
    Tn.prototype.doesHostExist = function(e) {
        var t = Ht.hostsConsent;
        return -1 !== t.indexOf(e + ":0") || -1 !== t.indexOf(e + ":1")
    }
    ,
    Tn.prototype.doesGenVendorExist = function(t) {
        return !!Nt.GeneralVendors && !!Nt.GeneralVendors.find(function(e) {
            return e.VendorCustomId === t
        })
    }
    ,
    Tn.prototype.doesVendorServiceExist = function(e) {
        return Ht.getVendorsInDomain().has(e)
    }
    ,
    Tn);
    function Tn() {}
    var In, Ln = (_n.prototype.insertCookiePolicyHtml = function() {
        if (qt(this.ONETRUST_COOKIE_POLICY).length) {
            var e, t = document.createDocumentFragment();
            if (hn.cookieListGroup) {
                var o = Nt.CookiesV2NewCookiePolicy ? ".ot-sdk-cookie-policy" : "#ot-sdk-cookie-policy-v2"
                  , n = document.createElement("div");
                qt(n).html(hn.cookieListGroup.html),
                n.removeChild(n.querySelector(o)),
                e = n.querySelector(".ot-sdk-cookie-policy"),
                Nt.useRTL && qt(e).attr("dir", "rtl")
            }
            e.querySelector("#cookie-policy-title").innerHTML = Nt.CookieListTitle || "",
            e.querySelector("#cookie-policy-description").innerHTML = Nt.CookieListDescription || "";
            var r = e.querySelector("section")
              , i = e.querySelector("section tbody tr")
              , s = null
              , a = null;
            Nt.CookiesV2NewCookiePolicy || (s = e.querySelector("section.subgroup"),
            a = e.querySelector("section.subgroup tbody tr"),
            qt(e).el.removeChild(e.querySelector("section.subgroup"))),
            qt(e).el.removeChild(e.querySelector("section")),
            !qt("#ot-sdk-cookie-policy").length && qt("#optanon-cookie-policy").length ? qt("#optanon-cookie-policy").append('<div id="ot-sdk-cookie-policy"></div>') : (qt("#ot-sdk-cookie-policy").html(""),
            qt("#optanon-cookie-policy").html(""));
            for (var l = 0; l < Nt.Groups.length; l++)
                if (Nt.CookiesV2NewCookiePolicy)
                    this.insertGroupHTMLV2(Nt, Nt.Groups, r, l, i, e, t);
                else if (this.insertGroupHTML(Nt, Nt.Groups, r, l, i, e, t),
                Nt.Groups[l].ShowSubgroup)
                    for (var c = 0; c < Nt.Groups[l].SubGroups.length; c++)
                        this.insertGroupHTML(Nt, Nt.Groups[l].SubGroups, s, c, a, e, t)
        }
    }
    ,
    _n.prototype.insertGroupHTMLV2 = function(a, e, t, o, l, n, r) {
        var i, c, s = this;
        function d(e) {
            return u.querySelector(e)
        }
        i = e[o];
        var u = t.cloneNode(!0)
          , p = e[o].SubGroups;
        qt(d("tbody")).html("");
        var h = i.Hosts.slice()
          , g = i.FirstPartyCookies.slice()
          , C = h.length || g.length ? i.GroupName : "";
        if (e[o].ShowSubgroup && p.length) {
            var y = u.querySelector("section.ot-sdk-subgroup ul li");
            p.forEach(function(e) {
                var t = y.cloneNode(!0);
                h = h.concat(e.Hosts),
                g = g.concat(e.FirstPartyCookies),
                (e.Hosts.length || e.FirstPartyCookies.length) && (C += "," + e.GroupName),
                qt(t.querySelector(".ot-sdk-cookie-policy-group")).html(e.GroupName),
                qt(t.querySelector(".ot-sdk-cookie-policy-group-desc")).html(s.groupsClass.safeFormattedGroupDescription(e)),
                qt(y.parentElement).append(t)
            }),
            u.querySelector("section.ot-sdk-subgroup ul").removeChild(y)
        } else
            u.removeChild(u.querySelector("section.ot-sdk-subgroup"));
        a.IsLifespanEnabled ? qt(d("th.ot-life-span")).el.innerHTML = a.LifespanText : qt(d("thead tr")).el.removeChild(qt(d("th.ot-life-span")).el),
        qt(d("th.ot-cookies")).el.innerHTML = a.CookiesText,
        qt(d("th.ot-host")).el.innerHTML = a.CategoriesText,
        qt(d("th.ot-cookies-type")).el.innerHTML = a.CookiesUsedText;
        var f = this.transformFirstPartyCookies(g, h, i)
          , v = !1;
        f.some(function(e) {
            return e.Description
        }) ? v = !0 : qt(d("thead tr")).el.removeChild(qt(d("th.ot-host-description")).el),
        qt(d(".ot-sdk-cookie-policy-group")).html(i.GroupName),
        qt(d(".ot-sdk-cookie-policy-group-desc")).html(this.groupsClass.safeFormattedGroupDescription(i));
        for (var k = function(e) {
            function t(e) {
                return o.querySelector(e)
            }
            var o = l.cloneNode(!0);
            qt(t(".ot-cookies-td span")).text(""),
            qt(t(".ot-life-span-td span")).text(""),
            qt(t(".ot-cookies-type span")).text(""),
            qt(t(".ot-cookies-td .ot-cookies-td-content")).html(""),
            qt(t(".ot-host-td")).html(""),
            qt(t(".ot-host-description-td")).html('<span class="ot-mobile-border"></span><p>' + f[e].Description + "</p> ");
            for (var n = [], r = [], i = 0; i < f[e].Cookies.length; i++)
                (c = f[e].Cookies[i]).IsSession ? n.push(a.LifespanTypeText) : n.push(Mt.getDuration(c)),
                r.push(f[e].Type ? '<a href="https://cookiepedia.co.uk/cookies/' + c.Name + '" rel="noopener" target="_blank" aria-label="' + c.Name + " " + Nt.NewWinTxt + '">' + c.Name + "</a>" : c.Name);
            qt(t(".ot-host-td")).append('<span class="ot-mobile-border"></span>'),
            t(".ot-host-td").setAttribute("data-label", a.CategoriesText),
            t(".ot-cookies-td").setAttribute("data-label", a.CookiesText),
            t(".ot-cookies-type").setAttribute("data-label", a.CookiesUsedText),
            t(".ot-life-span-td").setAttribute("data-label", a.LifespanText);
            var s = f[e].DisplayName || f[e].HostName;
            qt(t(".ot-host-td")).append(f[e].Type ? s : '<a href="https://cookiepedia.co.uk/host/' + c.Host + '" rel="noopener" target="_blank" aria-label="' + s + " " + Nt.NewWinTxt + '">' + s + "</a>"),
            t(".ot-cookies-td .ot-cookies-td-content").insertAdjacentHTML("beforeend", r.join(", ")),
            t(".ot-life-span-td .ot-life-span-td-content").innerText = n.join(", "),
            t(".ot-cookies-type .ot-cookies-type-td-content").innerText = f[e].Type ? Nt.firstPartyTxt : Nt.thirdPartyTxt,
            a.IsLifespanEnabled || o.removeChild(t("td.ot-life-span-td")),
            v || o.removeChild(t("td.ot-host-description-td")),
            qt(d("tbody")).append(o)
        }, m = 0; m < f.length; m++)
            k(m);
        0 === f.length ? u.removeChild(u.querySelector("table")) : qt(d("caption")).el.innerHTML = C,
        qt(n).append(u),
        qt(r).append(n),
        qt("#ot-sdk-cookie-policy").append(r)
    }
    ,
    _n.prototype.insertGroupHTML = function(a, e, t, o, l, n, r) {
        var i, s, c, d;
        function u(e) {
            return p.querySelector(e)
        }
        i = e[o];
        var p = t.cloneNode(!0);
        qt(u("caption")).el.innerHTML = i.GroupName,
        qt(u("tbody")).html(""),
        qt(u("thead tr")),
        a.IsLifespanEnabled ? qt(u("th.life-span")).el.innerHTML = a.LifespanText : qt(u("thead tr")).el.removeChild(qt(u("th.life-span")).el),
        qt(u("th.cookies")).el.innerHTML = a.CookiesText,
        qt(u("th.host")).el.innerHTML = a.CategoriesText;
        var h = !1;
        if (i.Hosts.some(function(e) {
            return e.description
        }) ? h = !0 : qt(u("thead tr")).el.removeChild(qt(u("th.host-description")).el),
        qt(u(".ot-sdk-cookie-policy-group")).html(i.GroupName),
        qt(u(".ot-sdk-cookie-policy-group-desc")).html(this.groupsClass.safeFormattedGroupDescription(i)),
        0 < i.FirstPartyCookies.length) {
            qt(u(".cookies-used-header")).html(a.CookiesUsedText),
            qt(u(".cookies-list")).html("");
            for (var g = 0; g < i.FirstPartyCookies.length; g++)
                s = i.FirstPartyCookies[g],
                qt(u(".cookies-list")).append("<li> " + Mt.getCookieLabel(s, a.AddLinksToCookiepedia) + " <li>")
        } else
            p.removeChild(u(".cookies-used-header")),
            p.removeChild(u(".cookies-list"));
        c = i.Hosts;
        for (var C = function(e) {
            function t(e) {
                return o.querySelector(e)
            }
            var o = l.cloneNode(!0);
            qt(t(".cookies-td ul")).html(""),
            qt(t(".life-span-td ul")).html(""),
            qt(t(".host-td")).html(""),
            qt(t(".host-description-td")).html('<span class="ot-mobile-border"></span><p>' + c[e].Description + "</p> ");
            for (var n = 0; n < c[e].Cookies.length; n++) {
                var r = "";
                r = (d = c[e].Cookies[n]).IsSession ? a.LifespanTypeText : 0 === d.Length ? "<1 " + a.LifespanDurationText || a.PCenterVendorListLifespanDays : d.Length + " " + a.LifespanDurationText || a.PCenterVendorListLifespanDays;
                var i = a.IsLifespanEnabled ? "&nbsp;(" + r + ")" : "";
                if (qt(t(".cookies-td ul")).append("<li> " + d.Name + " " + i + " </li>"),
                a.IsLifespanEnabled) {
                    var s = d.Length ? d.Length + " days" : "N/A";
                    qt(t(".life-span-td ul")).append("<li>" + s + "</li>")
                }
                0 === n && (qt(t(".host-td")).append('<span class="ot-mobile-border"></span>'),
                qt(t(".host-td")).append('<a href="https://cookiepedia.co.uk/host/' + d.Host + '" rel="noopener" target="_blank"\n                        aria-label="' + (c[e].DisplayName || c[e].HostName) + " " + Nt.NewWinTxt + '">' + (c[e].DisplayName || c[e].HostName) + "</a>"))
            }
            h || o.removeChild(t("td.host-description-td")),
            qt(u("tbody")).append(o)
        }, y = 0; y < c.length; y++)
            C(y);
        0 === c.length && qt(u("table")).el.removeChild(qt(u("thead")).el),
        qt(n).append(p),
        qt(r).append(n),
        qt("#ot-sdk-cookie-policy").append(r)
    }
    ,
    _n.prototype.transformFirstPartyCookies = function(e, t, o) {
        var n = this
          , r = t.slice();
        e.forEach(function(e) {
            n.populateHostGroup(e, r, Nt.firstPartyTxt)
        });
        var i = o.GeneralVendorsIds;
        this.populateGenVendor(i, o, r);
        var s = o.SubGroups;
        return s.length && s.forEach(function(e) {
            var t = e.GeneralVendorsIds;
            n.populateGenVendor(t, e, r)
        }),
        r
    }
    ,
    _n.prototype.populateGenVendor = function(e, o, n) {
        var r = this;
        e.length && e.forEach(function(t) {
            var e = Nt.GeneralVendors.find(function(e) {
                return e.VendorCustomId === t
            });
            e.Cookies.length && e.Cookies.forEach(function(e) {
                if (e.category === o.GroupName) {
                    var t = e.isThirdParty ? "" : Nt.firstPartyTxt;
                    r.populateHostGroup(e, n, t)
                }
            })
        })
    }
    ,
    _n.prototype.populateHostGroup = function(t, e, o) {
        e.some(function(e) {
            if (e.HostName === t.Host && e.Type === o)
                return e.Cookies.push(t),
                !0
        }) || e.unshift({
            HostName: t.Host,
            DisplayName: t.Host,
            HostId: "",
            Description: "",
            Type: o,
            Cookies: [t]
        })
    }
    ,
    _n);
    function _n() {
        this.groupsClass = Sn,
        this.ONETRUST_COOKIE_POLICY = "#ot-sdk-cookie-policy, #optanon-cookie-policy"
    }
    var Vn, Bn = function() {};
    var En, wn = (xn.prototype.updateFilterSelection = function(e) {
        var t, o;
        void 0 === e && (e = !1),
        o = e ? (t = Ht.filterByCategories,
        "data-optanongroupid") : (t = Ht.filterByIABCategories,
        "data-purposeid");
        for (var n = qt("#onetrust-pc-sdk .category-filter-handler").el, r = 0; r < n.length; r++) {
            var i = n[r].getAttribute(o)
              , s = -1 < t.indexOf(i);
            Bt.setCheckedAttribute(null, n[r], s)
        }
    }
    ,
    xn.prototype.cancelHostFilter = function() {
        for (var e = qt("#onetrust-pc-sdk .category-filter-handler").el, t = 0; t < e.length; t++) {
            var o = e[t].getAttribute("data-optanongroupid")
              , n = 0 <= Ht.filterByCategories.indexOf(o);
            Bt.setCheckedAttribute(null, e[t], n)
        }
    }
    ,
    xn.prototype.updateHostFilterList = function() {
        for (var e = qt("#onetrust-pc-sdk .category-filter-handler").el, t = 0; t < e.length; t++) {
            var o = e[t].getAttribute("data-optanongroupid");
            if (e[t].checked && Ht.filterByCategories.indexOf(o) < 0)
                Ht.filterByCategories.push(o);
            else if (!e[t].checked && -1 < Ht.filterByCategories.indexOf(o)) {
                var n = Ht.filterByCategories;
                Ht.filterByCategories.splice(n.indexOf(o), 1)
            }
        }
        return Ht.filterByCategories
    }
    ,
    xn.prototype.InitializeHostList = function() {
        Ht.hosts.hostTemplate = qt(Kt.P_Vendor_List + " " + Kt.P_Host_Cntr + " li").el[0].cloneNode(!0),
        Ht.hosts.hostCookieTemplate = qt(Kt.P_Vendor_List + " " + Kt.P_Host_Cntr + " " + Kt.P_Host_Opt + " li").el[0].cloneNode(!0)
    }
    ,
    xn.prototype.getCookiesForGroup = function(t) {
        var o = []
          , n = [];
        return t.FirstPartyCookies.length && t.FirstPartyCookies.forEach(function(e) {
            n.push(r(r({}, e), {
                groupName: t.GroupName
            }))
        }),
        t.Hosts.length && t.Hosts.forEach(function(e) {
            o.push(r(r({}, e), {
                isActive: "always active" === Xt.getGrpStatus(t).toLowerCase(),
                groupName: t.GroupName,
                Type: J.Host
            }))
        }),
        {
            firstPartyCookiesList: n,
            thirdPartyCookiesList: o
        }
    }
    ,
    xn.prototype.reactivateSrcTag = function(e) {
        var t = ["src"];
        e.setAttribute(t[0], e.getAttribute("data-" + t[0])),
        e.removeAttribute("data-src")
    }
    ,
    xn.prototype.reactivateScriptTag = function(e) {
        var t = e.parentNode
          , o = document.createElement(e.tagName);
        o.innerHTML = e.innerHTML;
        var n = e.attributes;
        if (0 < n.length)
            for (var r = 0; r < n.length; r++)
                "type" !== n[r].name ? o.setAttribute(n[r].name, n[r].value, !0) : o.setAttribute("type", "text/javascript", !0);
        t.appendChild(o),
        t.removeChild(e)
    }
    ,
    xn.prototype.reactivateTag = function(e, t) {
        var o, n = !0;
        if ((o = Ht.showVendorService ? e.className.match(/ot-vscat(-[a-zA-Z0-9,]+)+($|\s)/)[0].split(/ot-vscat-/i)[1].split("-") : e.className.match(/optanon-category(-[a-zA-Z0-9,]+)+($|\s)/)[0].split(/optanon-category-/i)[1].split("-")) && 0 < o.length) {
            for (var r = 0; r < o.length; r++)
                if (!Sn.canInsertForGroup(o[r].trim())) {
                    n = !1;
                    break
                }
            n && (t ? this.reactivateSrcTag(e) : this.reactivateScriptTag(e))
        }
    }
    ,
    xn.prototype.substitutePlainTextScriptTags = function() {
        var t = this
          , e = Ht.showVendorService ? "ot-vscat" : "optanon-category"
          , o = [].slice.call(document.querySelectorAll('script[class*="' + e + '"]'))
          , n = [].slice.call(document.querySelectorAll('*[class*="' + e + '"]'));
        Array.prototype.forEach.call(n, function(e) {
            "SCRIPT" !== e.tagName && e.hasAttribute("data-src") && t.reactivateTag(e, !0)
        }),
        Array.prototype.forEach.call(o, function(e) {
            e.hasAttribute("type") && "text/plain" === e.getAttribute("type") && t.reactivateTag(e, !1)
        })
    }
    ,
    xn);
    function xn() {}
    var Gn, On = (Nn.prototype.getSearchQuery = function(e) {
        var t = this
          , o = e.trim().split(/\s+/g);
        return new RegExp(o.map(function(e) {
            return t.escapeRegExp(e)
        }).join("|") + "(.+)?","gi")
    }
    ,
    Nn.prototype.escapeRegExp = function(e) {
        return e.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&")
    }
    ,
    Nn.prototype.setGlobalFilteredList = function(e) {
        return Ht.currentGlobalFilteredList = e
    }
    ,
    Nn.prototype.filterList = function(t, e, n) {
        var o = n && n.length;
        if ("" === t && !o)
            return this.setGlobalFilteredList(e);
        if (o) {
            var r = qt("#onetrust-pc-sdk " + Kt.P_Fltr_Options + " input").el.length
              , i = []
              , s = !1;
            r !== n.length ? e.forEach(function(o) {
                s = !0,
                o.vendorName && n.forEach(function(e) {
                    var t = parseInt(Ot.iabGrpIdMap[e]);
                    -1 < e.indexOf("IFEV2_") ? (o.features || []).forEach(function(e) {
                        e.featureId === t && i.push(o)
                    }) : -1 < e.indexOf("ISFV2_") ? o.specialFeatures.forEach(function(e) {
                        e.featureId === t && i.push(o)
                    }) : -1 < e.indexOf("ISPV2_") ? (o.specialPurposes || []).forEach(function(e) {
                        e.purposeId === t && i.push(o)
                    }) : (o.purposes.forEach(function(e) {
                        e.purposeId === t && i.push(o)
                    }),
                    o.legIntPurposes.forEach(function(e) {
                        e.purposeId === t && i.push(o)
                    }))
                })
            }) : i = e,
            s && (i = i.filter(function(e, t, o) {
                return o.indexOf(e) === t
            })),
            this.setGlobalFilteredList(i)
        }
        return "" === t ? Ht.currentGlobalFilteredList : Ht.currentGlobalFilteredList.filter(function(e) {
            if (e.vendorName)
                return e.vendorName.toLowerCase().includes(t.toLowerCase())
        })
    }
    ,
    Nn.prototype.loadVendorList = function(e, t) {
        void 0 === e && (e = "");
        var o = Ht.vendors;
        Ht.currentGlobalFilteredList = o.list,
        e ? (o.searchParam = e,
        Ht.filterByIABCategories = [],
        En.updateFilterSelection(!1)) : o.searchParam !== e ? o.searchParam = "" : t = Ht.filterByIABCategories;
        var n = this.filterList(o.searchParam, o.list, t);
        qt("#onetrust-pc-sdk " + Kt.P_Vendor_Content).el[0].scrollTop = 0,
        this.initVendorsData(e, n)
    }
    ,
    Nn.prototype.searchVendors = function(e, t, o, n) {
        if (n) {
            var r = this.getSearchQuery(n)
              , i = 0;
            for (var s in t)
                if (s) {
                    var a = o === oe.GoogleVendor ? s : t[s].VendorCustomId
                      , l = qt("" + e.vendorAccBtn + a).el[0].parentElement;
                    r.lastIndex = 0,
                    r.test(t[s][e.name]) ? (Lt(l, this._displayNull, !0),
                    i++) : Lt(l, "display: none;", !0)
                }
            0 === i ? (qt(e.accId).hide(),
            o === oe.GoogleVendor ? this.hasGoogleVendors = !1 : this.hasGenVendors = !1) : (o === oe.GoogleVendor ? this.hasGoogleVendors = !0 : this.hasGenVendors = !0,
            qt(e.accId).show()),
            this.showEmptyResults(!this.hasGoogleVendors && !this.hasIabVendors && !this.hasGenVendors, n)
        } else
            for (var c = qt(" " + e.venListId + ' li[style^="display: none"]').el, d = 0; d < c.length; d++)
                Lt(c[d], this._displayNull, !0);
        var u = qt("#onetrust-pc-sdk " + e.selectAllEvntHndlr).el[0];
        document.querySelector(e.venListId + ' li:not([style^="display: none"]) ' + e.ctgl + " > input[checked]") ? Bt.setCheckedAttribute("", u, !0) : Bt.setCheckedAttribute("", u, !1),
        document.querySelector(e.venListId + ' li:not([style^="display: none"]) ' + e.ctgl + " > input:not([checked])") ? u.parentElement.classList.add("line-through") : u.parentElement.classList.remove("line-through")
    }
    ,
    Nn.prototype.initGoogleVendors = function() {
        this.populateAddtlVendors(Ht.addtlVendorsList),
        this.venAdtlSelAllTglEvent()
    }
    ,
    Nn.prototype.initGenVendors = function() {
        this.populateGeneralVendors(),
        Nt.GenVenOptOut && Nt.GeneralVendors && Nt.GeneralVendors.length && this.genVenSelectAllTglEvent()
    }
    ,
    Nn.prototype.resetAddtlVendors = function() {
        Gn.searchVendors(Gn.googleSearchSelectors, Ht.addtlVendorsList, oe.GoogleVendor),
        this.showConsentHeader()
    }
    ,
    Nn.prototype.venAdtlSelAllTglEvent = function() {
        Gn.selectAllEventHandler({
            vendorsList: '#ot-addtl-venlst li:not([style^="display: none"]) .ot-ven-adtlctgl input',
            selAllCntr: "#onetrust-pc-sdk #ot-selall-adtlvencntr",
            selAllChkbox: "#onetrust-pc-sdk #ot-selall-adtlven-handler"
        })
    }
    ,
    Nn.prototype.genVenSelectAllTglEvent = function() {
        var e = {
            vendorsList: Kt.P_Gven_List + ' li:not([style^="display: none"]) .ot-ven-gvctgl input',
            selAllCntr: "#onetrust-pc-sdk #ot-selall-gnvencntr",
            selAllChkbox: "#onetrust-pc-sdk #ot-selall-gnven-handler"
        };
        Gn.selectAllEventHandler(e)
    }
    ,
    Nn.prototype.selectAllEventHandler = function(e) {
        for (var t = qt(e.vendorsList).el, o = qt(e.selAllCntr).el[0], n = qt(e.selAllChkbox).el[0], r = !0, i = 0; i < t.length; i++) {
            if (!t[i].checked) {
                r = !1;
                break
            }
            r = !0
        }
        o && (r ? o.classList.remove("line-through") : o.classList.add("line-through")),
        n.checked = !0;
        for (var s = 0; s < t.length && !t[s].checked; s++)
            s !== t.length - 1 || t[s].checked || (n.checked = !1);
        Bt.setCheckedAttribute("", n, n.checked)
    }
    ,
    Nn.prototype.vendorLegIntToggleEvent = function() {
        for (var e = qt(Kt.P_Vendor_Container + ' li:not([style^="display: none"]) .' + Kt.P_Ven_Ltgl + " input").el, t = qt("#onetrust-pc-sdk #" + Kt.P_Sel_All_Vendor_Leg_El).el[0], o = qt("#onetrust-pc-sdk #select-all-vendor-leg-handler").el[0], n = !0, r = 0; r < e.length; r++) {
            if (!e[r].checked) {
                n = !1;
                break
            }
            n = !0
        }
        n ? t.classList.remove("line-through") : t.classList.add("line-through"),
        o.checked = !0;
        for (var i = 0; i < e.length && !e[i].checked; i++)
            i !== e.length - 1 || e[i].checked || (o.checked = !1);
        Bt.setCheckedAttribute("", o, o.checked)
    }
    ,
    Nn.prototype.vendorsListEvent = function() {
        for (var e = qt(Kt.P_Vendor_Container + ' li:not([style^="display: none"]) .' + Kt.P_Ven_Ctgl + " input").el, t = qt("#onetrust-pc-sdk #" + Kt.P_Sel_All_Vendor_Consent_El).el[0], o = qt("#onetrust-pc-sdk #select-all-vendor-groups-handler").el[0], n = !0, r = 0; r < e.length; r++) {
            if (!e[r].checked) {
                n = !1;
                break
            }
            n = !0
        }
        n ? t.classList.remove("line-through") : t.classList.add("line-through"),
        o.checked = !0;
        for (var i = 0; i < e.length && !e[i].checked; i++)
            i !== e.length - 1 || e[i].checked || (o.checked = !1);
        Bt.setCheckedAttribute("", o, o.checked)
    }
    ,
    Nn.prototype.showEmptyResults = function(e, t, o) {
        void 0 === o && (o = !1);
        var n = qt("#onetrust-pc-sdk #no-results");
        e ? this.setNoResultsContent(t, o) : (qt("#onetrust-pc-sdk " + Kt.P_Vendor_Content).removeClass("no-results"),
        n.length && n.remove())
    }
    ,
    Nn.prototype.playSearchStatus = function(e) {
        var t = e ? document.querySelectorAll(Kt.P_Host_Cntr + " > li") : document.querySelectorAll(Kt.P_Vendor_Container + ' li:not([style$="none;"]),' + Kt.P_Gven_List + ' li:not([style$="none;"])')
          , o = t.length
          , n = qt('#onetrust-pc-sdk [role="status"]');
        o ? n.text(t.length + " " + (e ? "host" : "vendor") + (1 < o ? "s" : "") + " returned.") : n.el[0].textContent = ""
    }
    ,
    Nn.prototype.setNoResultsContent = function(e, t) {
        void 0 === t && (t = !1);
        var o = qt("#onetrust-pc-sdk #no-results").el[0];
        if (!o) {
            var n = document.createElement("div")
              , r = document.createElement("p")
              , i = document.createTextNode(" did not match any " + (t ? "hosts." : "vendors."))
              , s = document.createElement("span");
            return n.id = "no-results",
            s.id = "user-text",
            s.innerText = e,
            r.appendChild(s),
            r.appendChild(i),
            n.appendChild(r),
            qt("#onetrust-pc-sdk " + Kt.P_Vendor_Content).addClass("no-results"),
            qt("#vendor-search-handler").el[0].setAttribute("aria-describedby", n.id),
            qt("#onetrust-pc-sdk " + Kt.P_Vendor_Content).append(n)
        }
        o.querySelector("span").innerText = e
    }
    ,
    Nn.prototype.searchHostList = function(e) {
        var t = Ht.currentGlobalFilteredList;
        e && (t = this.searchList(e, t)),
        this.initHostData(e, t)
    }
    ,
    Nn.prototype.searchList = function(e, t) {
        var o = this.getSearchQuery(e);
        return t.filter(function(e) {
            return o.lastIndex = 0,
            o.test(e.DisplayName || e.HostName)
        })
    }
    ,
    Nn.prototype.setListSearchValues = function() {
        var e = Nt.PCenterVendorSearchAriaLabel
          , t = Nt.PCenterVendorListSearch
          , o = Nt.PCenterVendorsListText;
        Nt.showCookieList && !Nt.GeneralVendorsEnabled && (e = Nt.PCenterCookieSearchAriaLabel,
        t = Nt.PCenterCookieListSearch,
        o = Nt.PCenterCookiesListText),
        document.querySelector("#onetrust-pc-sdk " + Kt.P_Vendor_Title).innerText = o;
        var n = qt("#onetrust-pc-sdk " + Kt.P_Vendor_Search_Input);
        n.el[0].placeholder = t,
        n.attr("aria-label", e)
    }
    ,
    Nn.prototype.initHostData = function(e, d) {
        var u = this;
        Ht.optanonHostList = d;
        var p = It.isV2Template
          , h = Ot.pcName
          , g = Mt.isOptOutEnabled()
          , C = !1;
        this.setBackBtnTxt(),
        qt(Kt.P_Vendor_List + " #select-all-text-container p").html(Nt.PCenterAllowAllConsentText),
        qt("#onetrust-pc-sdk " + Kt.P_Vendor_Content + " ul" + Kt.P_Host_Cntr).html(""),
        this.showEmptyResults(d && 0 === d.length, e, !0),
        !It.isV2Template && h === st || this.setListSearchValues(),
        qt("#filter-btn-handler").el[0].setAttribute(this.ARIA_LABEL_ATTRIBUTE, Nt.PCenterCookieListFilterAria),
        qt("#filter-btn-handler title").html(Nt.PCenterCookieListFilterAria),
        It.isV2Template && qt("#ot-sel-blk span:first-child").html(Nt.PCenterAllowAllConsentText || Nt.ConsentText);
        for (var t = function(o) {
            var n = Ht.hosts.hostTemplate.cloneNode(!0)
              , e = n.querySelector("." + Kt.P_Host_Bx)
              , t = d[o].DisplayName || d[o].HostName;
            e && Bt.setHtmlAttributes(e, {
                id: "host-" + o,
                name: "host-" + o,
                "aria-label": t + " " + Nt.PCViewCookiesText,
                "aria-controls": "ot-host-acc-txt-" + o
            });
            var r = n.querySelector(Kt.P_Acc_Txt);
            if (r && Bt.setHtmlAttributes(r, {
                id: "ot-host-acc-txt-" + o,
                role: "region",
                "aria-labelledby": e.id
            }),
            !g || d[o].isFirstParty) {
                var i = n.querySelector(".ot-host-tgl");
                i && i.parentElement.removeChild(i)
            } else {
                var s = void 0;
                p ? ((s = Vn.chkboxEl.cloneNode(!0)).classList.add("ot-host-tgl"),
                s.querySelector("input").classList.add("host-checkbox-handler"),
                h === st ? n.querySelector(Kt.P_Host_Hdr).insertAdjacentElement("beforeBegin", s) : n.querySelector(Kt.P_Tgl_Cntr).insertAdjacentElement("beforeEnd", s)) : s = n.querySelector(".ot-host-tgl"),
                Bt.setHtmlAttributes(s.querySelector("input"), {
                    id: "ot-host-chkbox-" + o,
                    "aria-label": t,
                    hostId: d[o].HostId,
                    ckType: d[o].Type
                }),
                s.querySelector("label").setAttribute("for", "ot-host-chkbox-" + o),
                (d[o].Type === J.GenVendor ? Ht.genVendorsConsent[d[o].HostId] : -1 !== Ht.hostsConsent.indexOf(d[o].HostId + ":1")) ? (Bt.setCheckedAttribute(null, s.querySelector("input"), !0),
                d[o].isActive ? Bt.setDisabledAttribute(null, s.querySelector("input"), !0) : C = C || !0) : (C = !0,
                Bt.setCheckedAttribute(null, s.querySelector("input"), !1)),
                s.querySelector(Kt.P_Label_Txt).innerText = t
            }
            if (Nt.PCAccordionStyle === W.PlusMinus)
                n.querySelector(Kt.P_Acc_Header).insertAdjacentElement("afterBegin", Vn.plusMinusEl.cloneNode(!0));
            else if (p) {
                var a = Vn.arrowEl.cloneNode(!0);
                h === st ? n.querySelector(Kt.P_Host_View_Cookies).insertAdjacentElement("afterend", a) : n.querySelector(Kt.P_Tgl_Cntr).insertAdjacentElement("beforeEnd", a)
            }
            Nt.AddLinksToCookiepedia && !d[o].isFirstParty && (t = '\n                    <a  class="cookie-label"\n                        href="http://cookiepedia.co.uk/host/' + d[o].HostName + '"\n                        rel="noopener"\n                        target="_blank"\n                    >\n                        ' + t + '&nbsp;<span class="ot-scrn-rdr">' + Nt.NewWinTxt + "</span>\n                    </a>\n                "),
            n.querySelector(Kt.P_Host_Title).innerHTML = t,
            n.querySelector(Kt.P_Host_Desc).innerHTML = d[o].Description,
            d[o].PrivacyPolicy && Nt.pcShowCookieHost && n.querySelector(Kt.P_Host_Desc).insertAdjacentHTML("afterend", '<a href="' + d[o].PrivacyPolicy + '" rel="noopener" target="_blank">' + (p ? Nt.PCGVenPolicyTxt : Nt.PCCookiePolicyText) + '&nbsp;<span class="ot-scrn-rdr">' + Nt.NewWinTxt + "</span></a>");
            var l = n.querySelector(Kt.P_Host_View_Cookies);
            if (Ht.showGeneralVendors && !d[o].Cookies.length ? (Bt.removeChild(l),
            qt(n).addClass("ot-hide-acc")) : Nt.PCViewCookiesText && (l.innerHTML = Nt.PCViewCookiesText),
            !d[o].Description || !Nt.pcShowCookieHost) {
                var c = n.querySelector(Kt.P_Host_Desc);
                c.parentElement.removeChild(c)
            }
            qt(n.querySelector(Kt.P_Host_Opt)).html(""),
            d[o].Cookies.forEach(function(e) {
                var t = u.getCookieElement(e, d[o]);
                qt(n.querySelector(Kt.P_Host_Opt)).append(t)
            }),
            qt("#onetrust-pc-sdk " + Kt.P_Vendor_Content + " ul" + Kt.P_Host_Cntr).append(n)
        }, o = 0; o < d.length; o++)
            t(o);
        var n = 1 === d.length && d[0].HostName === Nt.PCFirstPartyCookieListText;
        if (Mt.isOptOutEnabled() && !n) {
            Bt.setDisabledAttribute("#onetrust-pc-sdk #select-all-hosts-groups-handler", null, !C);
            for (var r = qt("#onetrust-pc-sdk " + Kt.P_Host_Cntr + " .ot-host-tgl input").el, i = 0; i < r.length; i++)
                r[i].addEventListener("click", this.hostsListEvent);
            qt("#onetrust-pc-sdk " + Kt.P_Select_Cntr).removeClass("ot-hide"),
            this.hostsListEvent()
        } else
            qt("#onetrust-pc-sdk " + Kt.P_Select_Cntr).addClass("ot-hide")
    }
    ,
    Nn.prototype.hostsListEvent = function() {
        for (var e = qt("#onetrust-pc-sdk " + Kt.P_Host_Cntr + " .ot-host-tgl input").el, t = qt("#onetrust-pc-sdk #" + Kt.P_Sel_All_Host_El).el[0], o = qt("#onetrust-pc-sdk #select-all-hosts-groups-handler").el[0], n = qt("#onetrust-pc-sdk " + Kt.P_Cnsnt_Header).el[0], r = !0, i = 0; i < e.length; i++) {
            if (!e[i].checked) {
                r = !1;
                break
            }
            r = !0
        }
        r ? t.classList.remove("line-through") : t.classList.add("line-through"),
        o.checked = !0;
        for (var s = 0; s < e.length && !e[s].checked; s++)
            s !== e.length - 1 || e[s].checked || (o.checked = !1);
        Bt.setCheckedAttribute("", o, o.checked),
        o && n && o.setAttribute(this.ARIA_LABEL_ATTRIBUTE, n.textContent + " " + Nt.PCenterSelectAllVendorsText)
    }
    ,
    Nn.prototype.loadHostList = function(e, o) {
        void 0 === e && (e = "");
        var n = []
          , r = []
          , t = [];
        if (Ht.cookieListType !== X.GenVen && (Nt.Groups.forEach(function(e) {
            y(e.SubGroups, [e]).forEach(function(e) {
                if (o.length) {
                    if (-1 !== o.indexOf(e.CustomGroupId)) {
                        var t = En.getCookiesForGroup(e);
                        r = y(r, t.firstPartyCookiesList),
                        n = y(n, t.thirdPartyCookiesList)
                    }
                } else
                    t = En.getCookiesForGroup(e),
                    r = y(r, t.firstPartyCookiesList),
                    n = y(n, t.thirdPartyCookiesList)
            })
        }),
        r.length && n.unshift({
            HostName: Nt.PCFirstPartyCookieListText,
            DisplayName: Nt.PCFirstPartyCookieListText,
            HostId: "first-party-cookies-group",
            isFirstParty: !0,
            Cookies: r,
            Description: ""
        })),
        Ht.showGeneralVendors) {
            var i = this.getFilteredGenVendorsList(o)
              , s = this.mapGenVendorListToHostFormat(i);
            t = y(n, s)
        } else
            t = n;
        Ht.currentGlobalFilteredList = t,
        this.initHostData(e, t)
    }
    ,
    Nn.prototype.mapGenVendorListToHostFormat = function(e) {
        return e.map(function(e) {
            return {
                Cookies: e.Cookies,
                DisplayName: e.Name,
                HostName: e.Name,
                HostId: e.VendorCustomId,
                Description: e.Description,
                Type: J.GenVendor,
                PrivacyPolicy: e.PrivacyPolicyUrl,
                isActive: -1 < Ht.alwaysActiveGenVendors.indexOf(e.VendorCustomId)
            }
        })
    }
    ,
    Nn.prototype.mapGenVendorToHostFormat = function(e) {
        return {
            Cookies: e.Cookies,
            DisplayName: e.Name,
            HostName: e.Name,
            HostId: e.VendorCustomId,
            Description: e.Description,
            Type: J.GenVendor
        }
    }
    ,
    Nn.prototype.getFilteredGenVendorsList = function(t) {
        var o = []
          , e = [];
        if (t.length) {
            Nt.Groups.forEach(function(e) {
                y(e.SubGroups, [e]).forEach(function(e) {
                    -1 !== t.indexOf(e.CustomGroupId) && e.GeneralVendorsIds && e.GeneralVendorsIds.forEach(function(e) {
                        o.push(e)
                    })
                })
            });
            var n = Nt.GeneralVendors;
            return o.length && (e = n.filter(function(e) {
                if (-1 < o.indexOf(e.VendorCustomId))
                    return e
            })),
            e
        }
        return Nt.GeneralVendors
    }
    ,
    Nn.prototype.initVendorsData = function(e, t) {
        var o = this
          , n = t
          , r = Ht.vendors.list;
        if (this.setBackBtnTxt(),
        qt(Kt.P_Vendor_List + " #select-all-text-container p").html(Nt.PCenterAllowAllConsentText),
        It.isV2Template && (qt("#ot-sel-blk span:first-child").html(Nt.PCenterAllowAllConsentText || Nt.ConsentText),
        qt("#ot-sel-blk span:last-child").html(Nt.LegitInterestText),
        qt("#onetrust-pc-sdk " + Kt.P_Cnsnt_Header).html(Nt.PCenterAllowAllConsentText),
        Ot.legIntSettings.PAllowLI && !Ot.legIntSettings.PShowLegIntBtn && qt("#onetrust-pc-sdk .ot-sel-all-hdr .ot-li-hdr").html(Nt.PCenterLegitInterestText),
        Ot.legIntSettings.PAllowLI && !Ot.legIntSettings.PShowLegIntBtn || Lt(qt("#ot-sel-blk span:first-child").el[0], "max-width: 100%;", !0)),
        qt("#onetrust-pc-sdk #filter-btn-handler").el[0].setAttribute(this.ARIA_LABEL_ATTRIBUTE, Nt.PCenterVendorListFilterAria),
        qt("#onetrust-pc-sdk #filter-btn-handler title").html(Nt.PCenterVendorListFilterAria),
        this.hasIabVendors = 0 < n.length,
        this.showEmptyResults(!this.hasGoogleVendors && !this.hasIabVendors && !this.hasGenVendors, e, !1),
        0 === n.length ? qt("#ot-lst-cnt .ot-acc-cntr").hide() : qt("#ot-lst-cnt .ot-acc-cntr").show(),
        qt("#onetrust-pc-sdk " + Kt.P_Vendor_Container + " ." + Kt.P_Ven_Bx).length !== r.length && this.attachVendorsToDOM(),
        n.length !== r.length)
            r.forEach(function(e) {
                var t = qt(Kt.P_Vendor_Container + " #IAB" + e.vendorId).el[0].parentElement;
                -1 === n.indexOf(e) ? Lt(t, "display: none;", !0) : Lt(t, o._displayNull, !0)
            });
        else
            for (var i = qt(Kt.P_Vendor_Container + ' li[style^="display: none"]').el, s = 0; s < i.length; s++)
                Lt(i[s], this._displayNull, !0);
        !It.isV2Template && Ot.pcName === st || this.setListSearchValues();
        var a = document.querySelector("#vdr-lst-dsc");
        if (!a && Nt.PCenterVendorListDescText)
            if ((a = document.createElement("p")).id = "vdr-lst-dsc",
            qt(a).html(Nt.PCenterVendorListDescText),
            Ot.pcName !== st && Ot.pcName !== nt) {
                var l = document.querySelector("#onetrust-pc-sdk " + Kt.P_Vendor_Title_Elm);
                l && l.insertAdjacentElement("afterend", a)
            } else {
                var c = document.querySelector(Kt.P_Vendor_Content + " .ot-sdk-row");
                c && c.insertAdjacentElement("beforebegin", a)
            }
        qt("#onetrust-pc-sdk " + Kt.P_Select_Cntr).removeClass("ot-hide"),
        this.vendorsListEvent(),
        Ot.legIntSettings.PAllowLI && this.vendorLegIntToggleEvent()
    }
    ,
    Nn.prototype.updateVendorsDOMToggleStatus = function(e) {
        for (var t = qt(Kt.P_Vendor_Container + " " + Kt.P_Tgl_Cntr).el, o = 0; o < t.length; o++) {
            var n = t[o].querySelector("." + Kt.P_Ven_Ctgl + " input")
              , r = t[o].querySelector("." + Kt.P_Ven_Ltgl + " input");
            n && Bt.setCheckedAttribute("", n, e),
            r && Bt.setCheckedAttribute("", r, e)
        }
        var i = qt("#onetrust-pc-sdk #select-all-vendor-leg-handler").el[0];
        i && (i.parentElement.classList.remove("line-through"),
        Bt.setCheckedAttribute("", i, e));
        var s = qt("#onetrust-pc-sdk #select-all-vendor-groups-handler").el[0];
        s && (s.parentElement.classList.remove("line-through"),
        Bt.setCheckedAttribute("", s, e)),
        Nt.UseGoogleVendors && this.updateGoogleCheckbox(e),
        Ht.showGeneralVendors && Nt.GenVenOptOut && this.updateGenVenCheckbox(e)
    }
    ,
    Nn.prototype.updateGenVenCheckbox = function(e) {
        for (var t = qt(Kt.P_Gven_List + " .ot-ven-gvctgl input").el, o = 0; o < t.length; o++)
            Bt.setCheckedAttribute("", t[o], e);
        var n = qt("#onetrust-pc-sdk #ot-selall-gnven-handler").el[0];
        n && (n.parentElement.classList.remove("line-through"),
        Bt.setCheckedAttribute("", n, e))
    }
    ,
    Nn.prototype.updateGoogleCheckbox = function(e) {
        for (var t = qt("#ot-addtl-venlst .ot-tgl-cntr input").el, o = 0; o < t.length; o++)
            Bt.setCheckedAttribute("", t[o], e);
        var n = qt("#onetrust-pc-sdk #ot-selall-adtlven-handler").el[0];
        n && (n.parentElement.classList.remove("line-through"),
        Bt.setCheckedAttribute("", n, e))
    }
    ,
    Nn.prototype.updateVendorDisclosure = function(e, t) {
        var o = qt(Kt.P_Vendor_Container + " #IAB" + e).el[0].parentElement;
        if (t && t.disclosures) {
            var r = o.querySelector(Kt.P_Ven_Dets)
              , i = o.querySelector(Kt.P_Ven_Disc).cloneNode(!0)
              , n = i.cloneNode(!0);
            n.innerHTML = "<p><b>" + Nt.PCenterVendorListDisclosure + ": </b></p>",
            r.insertAdjacentElement("beforeend", n),
            t.disclosures.forEach(function(e) {
                var t = i.cloneNode(!0)
                  , o = "<p>" + Nt.PCenterVendorListStorageIdentifier + " </p> <p>" + (e.name || e.identifier) + " </p>";
                if (e.type && (o += "<p>" + Nt.PCenterVendorListStorageType + " </p> <p>" + e.type + " </p>"),
                e.maxAgeSeconds) {
                    var n = Bt.calculateCookieLifespan(e.maxAgeSeconds);
                    o += "<p>" + Nt.PCenterVendorListLifespan + " </p> <p>" + n + " </p>"
                }
                e.domain && (o += "<p>" + Nt.PCenterVendorListStorageDomain + " </p> <p>" + e.domain + " </p>"),
                e.purposes && (o += "<p>" + Nt.PCenterVendorListStoragePurposes + " </p> <p>" + e.purposes + " </p>"),
                t.innerHTML = o,
                r.insertAdjacentElement("beforeend", t)
            })
        }
    }
    ,
    Nn.prototype.addDescriptionElement = function(e, t) {
        var o = document.createElement("p");
        o.innerHTML = t || "",
        e.parentNode.insertBefore(o, e)
    }
    ,
    Nn.prototype.attachVendorsToDOM = function() {
        var R, q, M = Ht.vendors.list, U = Nt.IabType, j = Ot.pcName, z = Ht.vendors.vendorTemplate.cloneNode(!0);
        Ht.discVendors = {},
        It.isV2Template && (R = z.querySelector(".ot-ven-pur").cloneNode(!0),
        q = z.querySelector(Kt.P_Ven_Disc).cloneNode(!0),
        qt(z.querySelector(".ot-ven-dets")).html(""));
        for (var e = function(e) {
            var t = z.cloneNode(!0)
              , o = M[e].vendorId
              , n = M[e].vendorName
              , r = t.querySelector("." + Kt.P_Ven_Bx)
              , i = Ht.vendorsSetting[o]
              , s = t.querySelector(Kt.P_Ven_Link);
            Bt.setHtmlAttributes(r, {
                id: "IAB" + o,
                name: "IAB" + o,
                "aria-controls": "IAB-ACC-TXT" + o,
                "aria-label": n
            }),
            r.nextElementSibling.setAttribute("for", "IAB" + o),
            t.querySelector(Kt.P_Ven_Name).innerText = n,
            Bt.setHtmlAttributes(s, {
                href: M[e].policyUrl,
                rel: "noopener",
                target: "_blank"
            }),
            s.innerHTML = Nt.PCenterViewPrivacyPolicyText + "&nbsp;<span class='ot-scrn-rdr'>" + n + " " + Nt.NewWinTxt + "</span>";
            var a = It.isV2Template ? Vn.chkboxEl.cloneNode(!0) : t.querySelector(".ot-checkbox")
              , l = a.cloneNode(!0)
              , c = a.cloneNode(!0)
              , d = t.querySelector(Kt.P_Tgl_Cntr);
            It.isV2Template || a.parentElement.removeChild(a);
            var u = t.querySelector(Kt.P_Arrw_Cntr);
            if (i.consent) {
                c.classList.add(Kt.P_Ven_Ctgl);
                var p = -1 !== Ft.inArray(o + ":true", Ht.vendors.selectedVendors)
                  , h = c.querySelector("input");
                if (It.isV2Template) {
                    h.classList.add("vendor-checkbox-handler");
                    var g = c.querySelector(".ot-label-status");
                    Nt.PCShowConsentLabels ? g.innerHTML = p ? Nt.PCActiveText : Nt.PCInactiveText : Bt.removeChild(g)
                }
                Bt.setCheckedAttribute("", h, p),
                Bt.setHtmlAttributes(h, {
                    id: Kt.P_Vendor_CheckBx + "-" + e,
                    vendorid: o,
                    "aria-label": n
                }),
                c.querySelector("label").setAttribute("for", Kt.P_Vendor_CheckBx + "-" + e),
                c.querySelector(Kt.P_Label_Txt).textContent = n,
                j === st ? Nt.PCTemplateUpgrade ? d.insertAdjacentElement("beforeend", c) : qt(d).append(c) : d.insertBefore(c, u)
            }
            if (i.legInt && !i.specialPurposesOnly) {
                var C = -1 !== Ft.inArray(o + ":true", Ht.vendors.selectedLegIntVendors);
                if (Ot.legIntSettings.PShowLegIntBtn) {
                    var y = Qt.generateLegIntButtonElements(C, o, !0);
                    t.querySelector(Kt.P_Acc_Txt).insertAdjacentHTML("beforeend", y);
                    var f = t.querySelector(".ot-remove-objection-handler");
                    f && Lt(f, f.getAttribute("data-style"))
                } else
                    h = l.querySelector("input"),
                    It.isV2Template && (h.classList.add("vendor-checkbox-handler"),
                    g = l.querySelector(".ot-label-status"),
                    Nt.PCShowConsentLabels ? g.innerHTML = C ? Nt.PCActiveText : Nt.PCInactiveText : Bt.removeChild(g)),
                    l.classList.add(Kt.P_Ven_Ltgl),
                    h.classList.remove("vendor-checkbox-handler"),
                    h.classList.add("vendor-leg-checkbox-handler"),
                    Bt.setCheckedAttribute("", h, C),
                    Bt.setHtmlAttributes(h, {
                        id: Kt.P_Vendor_LegCheckBx + "-" + e,
                        "leg-vendorid": o,
                        "aria-label": n
                    }),
                    l.querySelector("label").setAttribute("for", Kt.P_Vendor_LegCheckBx + "-" + e),
                    l.querySelector(Kt.P_Label_Txt).textContent = n,
                    t.querySelector("." + Kt.P_Ven_Ctgl) && (u = t.querySelector("." + Kt.P_Ven_Ctgl)),
                    j !== st || d.children.length ? d.insertBefore(l, u) : qt(d).append(l),
                    i.consent || j !== st || l.classList.add(Kt.P_Ven_Ltgl_Only)
            }
            It.isV2Template && (d.insertAdjacentElement("beforeend", Vn.arrowEl.cloneNode(!0)),
            Nt.PCAccordionStyle !== W.Caret && t.querySelector(".ot-ven-hdr").insertAdjacentElement("beforebegin", Vn.plusMinusEl.cloneNode(!0)));
            var v = t.querySelector(Kt.P_Acc_Txt);
            if (v && Bt.setHtmlAttributes(v, {
                id: "IAB-ACC-TXT" + o,
                "aria-labelledby": "IAB-ACC-TXT" + o,
                role: "region"
            }),
            M[e].deviceStorageDisclosureUrl && (Bt.setHtmlAttributes(r, {
                "disc-vid": o
            }),
            Ht.discVendors[o] = {
                isFetched: !1,
                disclosureUrl: M[e].deviceStorageDisclosureUrl
            }),
            It.isV2Template)
                K.populateVendorDetailsHtml(t, R, M[e], q);
            else {
                var k = t.querySelector(".vendor-option-purpose")
                  , m = t.querySelector(".vendor-consent-group")
                  , b = t.querySelector(".legitimate-interest")
                  , P = t.querySelector(".legitimate-interest-group")
                  , S = t.querySelector(".spl-purpose")
                  , A = t.querySelector(".spl-purpose-grp")
                  , T = t.querySelector(".vendor-feature")
                  , I = t.querySelector(".vendor-feature-group")
                  , L = t.querySelector(".vendor-spl-feature")
                  , _ = t.querySelector(".vendor-spl-feature-grp")
                  , V = m.cloneNode(!0)
                  , B = P.cloneNode(!0)
                  , E = A.cloneNode(!0)
                  , w = I.cloneNode(!0)
                  , x = _.cloneNode(!0);
                q = t.querySelector(Kt.P_Ven_Disc);
                var G = t.querySelector(Kt.P_Ven_Dets)
                  , O = q.cloneNode(!0);
                q.parentElement.removeChild(q),
                K.attachVendorDisclosure(O, M[e]),
                G.insertAdjacentElement("afterbegin", O),
                m.parentElement.removeChild(m),
                i.consent && (qt(k.querySelector("p")).text(Nt.ConsentPurposesText),
                M[e].purposes.forEach(function(e) {
                    qt(V.querySelector(".consent-category")).text(e.purposeName);
                    var t = V.querySelector(".consent-status");
                    t && V.removeChild(t),
                    b.insertAdjacentHTML("beforebegin", V.outerHTML)
                })),
                i.consent || k.parentElement.removeChild(k);
                var N = B.querySelector(".vendor-opt-out-handler");
                "IAB2" === Nt.IabType && N.parentElement.removeChild(N),
                P.parentElement.removeChild(P),
                i.legInt && (qt(b.querySelector("p")).text(Nt.LegitimateInterestPurposesText),
                Ot.legIntSettings.PAllowLI && "IAB2" === Nt.IabType && M[e].legIntPurposes.forEach(function(e) {
                    qt(B.querySelector(".consent-category")).text(e.purposeName),
                    b.insertAdjacentHTML("afterend", B.outerHTML)
                })),
                i.legInt || b.parentElement.removeChild(b),
                A.parentElement.removeChild(A),
                "IAB2" === U && M[e].specialPurposes.forEach(function(e) {
                    qt(E.querySelector(".consent-category")).text(e.purposeName),
                    S.insertAdjacentHTML("afterend", E.outerHTML)
                }),
                0 === M[e].specialPurposes.length ? S.parentElement.removeChild(S) : qt(S.querySelector("p")).text(Nt.SpecialPurposesText),
                I.parentElement.removeChild(I),
                qt(T.querySelector("p")).text(Nt.FeaturesText),
                M[e].features.forEach(function(e) {
                    qt(w.querySelector(".consent-category")).text(e.featureName),
                    T.insertAdjacentHTML("afterend", w.outerHTML)
                }),
                0 === M[e].features.length && T.parentElement.removeChild(T),
                L.parentElement.removeChild(_),
                "IAB2" === U && M[e].specialFeatures.forEach(function(e) {
                    qt(x.querySelector(".consent-category")).text(e.featureName),
                    L.insertAdjacentHTML("afterend", x.outerHTML)
                }),
                0 === M[e].specialFeatures.length ? L.parentElement.removeChild(L) : qt(L.querySelector("p")).text(Nt.SpecialFeaturesText);
                var D = r.parentElement.querySelector(".vendor-purposes p");
                D.parentElement.removeChild(D)
            }
            qt("#onetrust-pc-sdk " + Kt.P_Vendor_Container).append(t);
            var H = qt("#onetrust-pc-sdk " + Kt.P_Sel_All_Vendor_Consent_Handler).el[0];
            H && H.setAttribute(K.ARIA_LABEL_ATTRIBUTE, Nt.PCenterSelectAllVendorsText + " " + Nt.LegitInterestText);
            var F = qt("#onetrust-pc-sdk " + Kt.P_Sel_All_Vendor_Leg_Handler).el[0];
            F && F.setAttribute(K.ARIA_LABEL_ATTRIBUTE, Nt.PCenterSelectAllVendorsText + " " + Nt.ConsentText)
        }, K = this, t = 0; t < M.length; t++)
            e(t)
    }
    ,
    Nn.prototype.populateVendorDetailsHtml = function(e, t, o, n) {
        var r = e.querySelector(".ot-ven-dets")
          , i = Ht.vendorsSetting[o.vendorId]
          , s = n.cloneNode(!0);
        if (this.attachVendorDisclosure(s, o),
        r.insertAdjacentElement("beforeEnd", s),
        i.consent) {
            var a = t.cloneNode(!0)
              , l = "<h4>" + Nt.ConsentPurposesText + "</h4>";
            l += "<ul>",
            o.purposes.forEach(function(e) {
                l += "<li><p>" + e.purposeName + "</p></li>"
            }),
            l += "</ul>",
            a.innerHTML = l,
            r.insertAdjacentElement("beforeEnd", a)
        }
        if (i.legInt && o.legIntPurposes.length) {
            var c = t.cloneNode(!0)
              , d = "<h4>" + Nt.LegitimateInterestPurposesText + "</h4>";
            d += "<ul>",
            o.legIntPurposes.forEach(function(e) {
                d += "<li><p>" + e.purposeName + "</p></li>"
            }),
            d += "</ul>",
            c.innerHTML = d,
            r.insertAdjacentElement("beforeEnd", c)
        }
        if ("IAB2" === Ot.iabType && o.specialPurposes.length) {
            var u = t.cloneNode(!0)
              , p = "<h4>" + Nt.SpecialPurposesText + "</h4>";
            p += "<ul>",
            o.specialPurposes.forEach(function(e) {
                p += "<li><p>" + e.purposeName + "</p></li>"
            }),
            p += "</ul>",
            u.innerHTML = p,
            r.insertAdjacentElement("beforeEnd", u)
        }
        if (o.features.length) {
            var h = t.cloneNode(!0)
              , g = "<h4>" + Nt.FeaturesText + "</h4>";
            g += "<ul>",
            o.features.forEach(function(e) {
                g += "<li><p>" + e.featureName + "</p></li>"
            }),
            g += "</ul>",
            h.innerHTML = g,
            r.insertAdjacentElement("beforeEnd", h)
        }
        if ("IAB2" === Ot.iabType && o.specialFeatures.length) {
            var C = t.cloneNode(!0)
              , y = "<h4>" + Nt.SpecialFeaturesText + "</h4>";
            y += "<ul>",
            o.specialFeatures.forEach(function(e) {
                y += "<li><p>" + e.featureName + "</p></li>"
            }),
            y += "</ul>",
            C.innerHTML = y,
            r.insertAdjacentElement("beforeEnd", C)
        }
    }
    ,
    Nn.prototype.InitializeVendorList = function() {
        if (Ht.vendors.list = Ht.iabData ? Ht.iabData.vendors : null,
        Ht.vendors.vendorTemplate = qt(Kt.P_Vendor_Container + " li").el[0].cloneNode(!0),
        qt("#onetrust-pc-sdk " + Kt.P_Vendor_Container).html(""),
        !It.isV2Template && Ot.pcName === st) {
            var e, t = Ht.vendors.vendorTemplate.querySelectorAll(Kt.P_Acc_Header);
            Ot.legIntSettings.PAllowLI && "IAB2" === Ot.iabType ? (e = t[0]).parentElement.removeChild(e) : (e = t[1]).parentElement.removeChild(e)
        }
    }
    ,
    Nn.prototype.cancelVendorFilter = function() {
        for (var e = qt("#onetrust-pc-sdk .category-filter-handler").el, t = 0; t < e.length; t++) {
            var o = e[t].getAttribute("data-purposeid")
              , n = 0 <= Ht.filterByIABCategories.indexOf(o);
            Bt.setCheckedAttribute(null, e[t], n)
        }
    }
    ,
    Nn.prototype.attachVendorDisclosure = function(e, t) {
        var o = "<h4>" + Nt.PCenterVendorListLifespan + " :</h4><span> " + t.cookieMaxAge + "</span>";
        t.usesNonCookieAccess && (o += "<p>" + Nt.PCenterVendorListNonCookieUsage + "</p>"),
        e.innerHTML = o
    }
    ,
    Nn.prototype.updateVendorFilterList = function() {
        for (var e = qt("#onetrust-pc-sdk .category-filter-handler").el, t = 0; t < e.length; t++) {
            var o = e[t].getAttribute("data-purposeid");
            if (e[t].checked && Ht.filterByIABCategories.indexOf(o) < 0)
                Ht.filterByIABCategories.push(o);
            else if (!e[t].checked && -1 < Ht.filterByIABCategories.indexOf(o)) {
                var n = Ht.filterByIABCategories;
                Ht.filterByIABCategories.splice(n.indexOf(o), 1)
            }
        }
        return Ht.filterByIABCategories
    }
    ,
    Nn.prototype.saveVendorStatus = function() {
        var e = Ht.vendors
          , t = Ht.oneTrustIABConsent;
        t.purpose = e.selectedPurpose.slice(),
        t.legimateInterest = e.selectedLegInt.slice(),
        t.vendors = e.selectedVendors.slice(),
        t.legIntVendors = e.selectedLegIntVendors.slice(),
        t.specialFeatures = e.selectedSpecialFeatures.slice();
        var o = Ht.addtlVendors;
        o.vendorConsent = Object.keys(o.vendorSelected)
    }
    ,
    Nn.prototype.updateIabVariableReference = function() {
        var e = Ht.oneTrustIABConsent
          , t = Ht.vendors;
        t.selectedPurpose = e.purpose.slice(),
        t.selectedLegInt = e.legimateInterest.slice(),
        t.selectedVendors = e.vendors.slice(),
        t.selectedLegIntVendors = e.legIntVendors.slice(),
        t.selectedSpecialFeatures = e.specialFeatures.slice();
        var o = Ht.addtlVendors;
        o.vendorSelected = {},
        o.vendorConsent.forEach(function(e) {
            o.vendorSelected[e] = !0
        })
    }
    ,
    Nn.prototype.allowAllhandler = function() {
        hn.initializeIABData(!0, !1)
    }
    ,
    Nn.prototype.rejectAllHandler = function() {
        hn.initializeIABData(!1, !0)
    }
    ,
    Nn.prototype.populateAddtlVendors = function(e) {
        var t = Nt.PCAccordionStyle === W.Caret ? Vn.arrowEl.cloneNode(!0) : Vn.plusMinusEl.cloneNode(!0)
          , o = document.querySelector("#onetrust-pc-sdk .ot-sel-all-chkbox")
          , n = o.cloneNode(!0);
        Bt.removeChild(n.querySelector("#ot-selall-hostcntr")),
        Bt.removeChild(o.querySelector("#ot-selall-vencntr")),
        Bt.removeChild(o.querySelector("#ot-selall-licntr"));
        var r = Vn.accordionEl.cloneNode(!0);
        r.classList.add("ot-iab-acc"),
        r.querySelector(".ot-acc-hdr").insertAdjacentElement("beforeEnd", t.cloneNode(!0)),
        r.querySelector(".ot-acc-hdr").insertAdjacentHTML("beforeEnd", "<div class='ot-vensec-title'>" + Nt.PCIABVendorsText + "</div>"),
        r.querySelector(".ot-acc-hdr").insertAdjacentElement("beforeEnd", n),
        r.querySelector(".ot-acc-txt").insertAdjacentElement("beforeEnd", qt("#ot-ven-lst").el[0]),
        qt("#ot-lst-cnt .ot-sdk-column").append(r),
        r.querySelector("button").setAttribute(this.ARIA_LABEL_ATTRIBUTE, Nt.PCIABVendorsText),
        this.iabAccInit = !0;
        var i = n.cloneNode(!0);
        Bt.removeChild(i.querySelector("#ot-selall-licntr")),
        i.querySelector(".ot-chkbox").id = "ot-selall-adtlvencntr",
        i.querySelector("input").id = "ot-selall-adtlven-handler",
        i.querySelector("label").setAttribute("for", "ot-selall-adtlven-handler");
        var s = Vn.accordionEl.cloneNode(!0);
        s.querySelector(".ot-acc-hdr").insertAdjacentElement("beforeEnd", t.cloneNode(!0)),
        s.querySelector(".ot-acc-hdr").insertAdjacentHTML("beforeEnd", "<div class='ot-vensec-title'>" + Nt.PCGoogleVendorsText + "</div>"),
        s.querySelector(".ot-acc-hdr").insertAdjacentElement("beforeEnd", i),
        s.querySelector(".ot-acc-txt").insertAdjacentHTML("beforeEnd", "<ul id='ot-addtl-venlst'></ul>"),
        s.classList.add("ot-adtlv-acc"),
        s.querySelector("button").setAttribute(this.ARIA_LABEL_ATTRIBUTE, Nt.PCGoogleVendorsText);
        var a = Ht.vendors.vendorTemplate.cloneNode(!0);
        for (var l in a.querySelector("button").classList.remove("ot-ven-box"),
        a.querySelector("button").classList.add("ot-addtl-venbox"),
        Bt.removeChild(a.querySelector(".ot-acc-txt")),
        e)
            if (e[l]) {
                var c = a.cloneNode(!0)
                  , d = e[l].name;
                c.querySelector(Kt.P_Ven_Name).innerText = d;
                var u = c.querySelector("button");
                Bt.setHtmlAttributes(u, {
                    id: "Adtl-IAB" + l
                }),
                Bt.setHtmlAttributes(c.querySelector(Kt.P_Ven_Link), {
                    href: e[l].policyUrl,
                    rel: "noopener",
                    target: "_blank"
                }),
                c.querySelector(Kt.P_Ven_Link).innerHTML = Nt.PCenterViewPrivacyPolicyText + "&nbsp;<span class='ot-scrn-rdr'>" + d + " " + Nt.NewWinTxt + "</span>";
                var p = Vn.chkboxEl.cloneNode(!0);
                p.classList.remove("ot-ven-ctgl"),
                p.classList.add("ot-ven-adtlctgl");
                var h = Boolean(Ht.addtlVendors.vendorSelected[l])
                  , g = p.querySelector("input");
                g.classList.add("ot-addtlven-chkbox-handler");
                var C = p.querySelector(".ot-label-status");
                Nt.PCShowConsentLabels ? C.innerHTML = h ? Nt.PCActiveText : Nt.PCInactiveText : Bt.removeChild(C),
                Bt.setCheckedAttribute("", g, h),
                Bt.setHtmlAttributes(g, {
                    id: "ot-addtlven-chkbox-" + l,
                    "addtl-vid": l,
                    "aria-label": d
                }),
                p.querySelector("label").setAttribute("for", "ot-addtlven-chkbox-" + l),
                p.querySelector(Kt.P_Label_Txt).textContent = d;
                var y = c.querySelector(Kt.P_Tgl_Cntr);
                qt(y).append(p),
                y.insertAdjacentElement("beforeend", Vn.arrowEl.cloneNode(!0)),
                Nt.PCAccordionStyle !== W.Caret && c.querySelector(".ot-ven-hdr").insertAdjacentElement("beforebegin", Vn.plusMinusEl.cloneNode(!0)),
                qt(s.querySelector("#ot-addtl-venlst")).append(c)
            }
        qt("#ot-lst-cnt .ot-sdk-column").append(s),
        qt("#onetrust-pc-sdk").on("click", "#ot-pc-lst .ot-acc-cntr > input", function(e) {
            Bt.setCheckedAttribute(null, e.target, e.target.checked)
        }),
        this.showConsentHeader()
    }
    ,
    Nn.prototype.populateGeneralVendors = function() {
        var p = this
          , e = Nt.GeneralVendors
          , t = document.querySelector(".ot-gv-acc")
          , h = !!t;
        if (!e.length)
            return this.hasGenVendors = !1,
            void (t && qt(t).hide());
        this.hasGenVendors = !0,
        t && qt(t).show();
        var o = Nt.PCAccordionStyle === W.Caret ? Vn.arrowEl.cloneNode(!0) : Vn.plusMinusEl.cloneNode(!0);
        this.iabAccInit || this.addIabAccordion();
        var n = document.createElement("div");
        n.setAttribute("class", "ot-sel-all-chkbox");
        var r = Vn.chkboxEl.cloneNode(!0);
        r.id = "ot-selall-gnvencntr",
        r.querySelector("input").id = "ot-selall-gnven-handler",
        r.querySelector("label").setAttribute("for", "ot-selall-gnven-handler"),
        qt(n).append(r);
        var g = Vn.accordionEl.cloneNode(!0);
        g.querySelector(".ot-acc-hdr").insertAdjacentElement("beforeEnd", o.cloneNode(!0)),
        g.querySelector(".ot-acc-hdr").insertAdjacentHTML("beforeEnd", "<div class='ot-vensec-title'>" + Nt.PCenterGeneralVendorsText + "</div>"),
        Nt.GenVenOptOut && g.querySelector(".ot-acc-hdr").insertAdjacentElement("beforeEnd", n),
        g.querySelector(".ot-acc-txt").insertAdjacentHTML("beforeEnd", "<ul id='ot-gn-venlst'></ul>"),
        g.classList.add("ot-gv-acc"),
        g.querySelector("button").setAttribute(this.ARIA_LABEL_ATTRIBUTE, Nt.PCenterGeneralVendorsText);
        var C = Ht.vendors.vendorTemplate.cloneNode(!0);
        C.querySelector("button").classList.remove("ot-ven-box"),
        C.querySelector("button").classList.add("ot-gv-venbox"),
        qt(C.querySelector(".ot-acc-txt")).html('<ul class="ot-host-opt"></ul>'),
        h && qt("" + Kt.P_Gven_List).html("");
        var y = !0;
        e.forEach(function(e) {
            var o = p.mapGenVendorToHostFormat(e)
              , n = C.cloneNode(!0)
              , t = e.VendorCustomId
              , r = e.Name
              , i = n.querySelector(Kt.P_Ven_Link);
            n.querySelector(Kt.P_Ven_Name).innerText = r;
            var s = n.querySelector("button");
            if (Bt.setHtmlAttributes(s, {
                id: "Gn-" + t
            }),
            e.PrivacyPolicyUrl ? (Bt.setHtmlAttributes(i, {
                href: e.PrivacyPolicyUrl,
                rel: "noopener",
                target: "_blank"
            }),
            i.innerHTML = Nt.PCGVenPolicyTxt + "&nbsp;<span class='ot-scrn-rdr'>" + r + " " + Nt.NewWinTxt + "</span>") : i.classList.add("ot-hide"),
            p.addDescriptionElement(i, e.Description),
            Nt.GenVenOptOut) {
                var a = Vn.chkboxEl.cloneNode(!0);
                a.classList.remove("ot-ven-ctgl"),
                a.classList.add("ot-ven-gvctgl");
                var l = Boolean(Ht.genVendorsConsent[t])
                  , c = a.querySelector("input");
                c.classList.add("ot-gnven-chkbox-handler");
                var d = a.querySelector(".ot-label-status");
                Nt.PCShowConsentLabels ? d.innerHTML = l ? Nt.PCActiveText : Nt.PCInactiveText : Bt.removeChild(d),
                Bt.setCheckedAttribute("", c, l),
                Bt.setHtmlAttributes(c, {
                    id: "ot-gnven-chkbox-" + t,
                    "gn-vid": t,
                    "aria-label": r
                }),
                go.isGenVenPartOfAlwaysActiveGroup(t) ? Bt.setDisabledAttribute(null, c, !0) : y = !1,
                a.querySelector("label").setAttribute("for", "ot-gnven-chkbox-" + t),
                a.querySelector(Kt.P_Label_Txt).textContent = r;
                var u = n.querySelector(Kt.P_Tgl_Cntr);
                qt(u).append(a),
                u.insertAdjacentElement("beforeend", Vn.arrowEl.cloneNode(!0))
            }
            Nt.PCAccordionStyle !== W.Caret && n.querySelector(".ot-ven-hdr").insertAdjacentElement("beforebegin", Vn.plusMinusEl.cloneNode(!0)),
            e.Cookies.length || qt(n).addClass("ot-hide-acc"),
            e.Cookies.forEach(function(e) {
                var t = p.getCookieElement(e, o);
                qt(n.querySelector(".ot-host-opt")).append(t)
            }),
            h ? qt("" + Kt.P_Gven_List).append(n) : qt(g.querySelector("" + Kt.P_Gven_List)).append(n)
        }),
        h || qt("#ot-lst-cnt .ot-sdk-column").append(g),
        qt("#onetrust-pc-sdk").on("click", "#ot-pc-lst .ot-acc-cntr > input", function(e) {
            Bt.setCheckedAttribute(null, e.target, e.target.checked)
        }),
        this.showConsentHeader(),
        y && Bt.setDisabledAttribute("#ot-selall-gnven-handler", null, !0)
    }
    ,
    Nn.prototype.addIabAccordion = function() {
        var e = Nt.PCAccordionStyle === W.Caret ? Vn.arrowEl.cloneNode(!0) : Vn.plusMinusEl.cloneNode(!0)
          , t = document.querySelector("#onetrust-pc-sdk .ot-sel-all-chkbox")
          , o = t.cloneNode(!0);
        Bt.removeChild(o.querySelector("#ot-selall-hostcntr")),
        Bt.removeChild(t.querySelector("#ot-selall-vencntr")),
        Bt.removeChild(t.querySelector("#ot-selall-licntr"));
        var n = Vn.accordionEl.cloneNode(!0);
        n.classList.add("ot-iab-acc"),
        n.querySelector(".ot-acc-hdr").insertAdjacentElement("beforeEnd", e.cloneNode(!0)),
        n.querySelector(".ot-acc-hdr").insertAdjacentHTML("beforeEnd", "<div class='ot-vensec-title'>" + Nt.PCIABVendorsText + "</div>"),
        n.querySelector(".ot-acc-hdr").insertAdjacentElement("beforeEnd", o),
        n.querySelector(".ot-acc-txt").insertAdjacentElement("beforeEnd", qt("#ot-ven-lst").el[0]),
        qt("#ot-lst-cnt .ot-sdk-column").append(n),
        n.querySelector("button").setAttribute(this.ARIA_LABEL_ATTRIBUTE, Nt.PCIABVendorsText),
        this.iabAccInit = !0
    }
    ,
    Nn.prototype.showConsentHeader = function() {
        var e = Ot.legIntSettings;
        qt("#onetrust-pc-sdk .ot-sel-all-hdr").show(),
        e.PAllowLI && !e.PShowLegIntBtn || qt("#onetrust-pc-sdk .ot-li-hdr").hide()
    }
    ,
    Nn.prototype.setBackBtnTxt = function() {
        It.isV2Template ? (qt(Kt.P_Vendor_List + " .back-btn-handler").attr(this.ARIA_LABEL_ATTRIBUTE, Nt.PCenterBackText),
        qt(Kt.P_Vendor_List + " .back-btn-handler title").html(Nt.PCenterBackText)) : qt(Kt.P_Vendor_List + " .back-btn-handler .pc-back-button-text").html(Nt.PCenterBackText)
    }
    ,
    Nn.prototype.getCookieElement = function(e, t) {
        var o = Ht.hosts.hostCookieTemplate.cloneNode(!0)
          , n = o.querySelector("div").cloneNode(!0);
        n.classList.remove("cookie-name-container"),
        qt(o).html("");
        var r = e.Name;
        Nt.AddLinksToCookiepedia && t.isFirstParty && (r = Mt.getCookieLabel(e, Nt.AddLinksToCookiepedia));
        var i = n.cloneNode(!0);
        if (i.classList.add(Kt.P_c_Name),
        i.querySelector("div:nth-child(1)").innerHTML = Nt.pcCListName,
        i.querySelector("div:nth-child(2)").innerHTML = r,
        qt(o).append(i),
        Nt.pcShowCookieHost) {
            var s = n.cloneNode(!0);
            s.classList.add(Kt.P_c_Host),
            s.querySelector("div:nth-child(1)").innerHTML = Nt.pcCListHost,
            s.querySelector("div:nth-child(2)").innerHTML = e.Host,
            qt(o).append(s)
        }
        if (Nt.pcShowCookieDuration) {
            var a = n.cloneNode(!0);
            a.classList.add(Kt.P_c_Duration),
            a.querySelector("div:nth-child(1)").innerHTML = Nt.pcCListDuration,
            a.querySelector("div:nth-child(2)").innerHTML = e.IsSession ? Nt.LifespanTypeText : Mt.getDuration(e),
            qt(o).append(a)
        }
        if (Nt.pcShowCookieType) {
            var l = t.Type === J.GenVendor ? !e.isThirdParty : t.isFirstParty
              , c = n.cloneNode(!0);
            c.classList.add(Kt.P_c_Type),
            c.querySelector("div:nth-child(1)").innerHTML = Nt.pcCListType,
            c.querySelector("div:nth-child(2)").innerHTML = l ? Nt.firstPartyTxt : Nt.thirdPartyTxt,
            qt(o).append(c)
        }
        if (Nt.pcShowCookieCategory) {
            var d = void 0;
            if (d = t.Type === J.GenVendor ? e.category : t.isFirstParty ? e.groupName : t.groupName) {
                var u = n.cloneNode(!0);
                u.classList.add(Kt.P_c_Category),
                u.querySelector("div:nth-child(1)").innerHTML = Nt.pcCListCategory,
                u.querySelector("div:nth-child(2)").innerHTML = d,
                qt(o).append(u)
            }
        }
        if (Nt.pcShowCookieDescription && e.description) {
            var p = n.cloneNode(!0);
            p.classList.add(Kt.P_c_Desc),
            p.querySelector("div:nth-child(1)").innerHTML = Nt.pcCListDescription,
            p.querySelector("div:nth-child(2)").innerHTML = e.description,
            qt(o).append(p)
        }
        return o
    }
    ,
    Nn);
    function Nn() {
        this.hasIabVendors = !1,
        this.hasGoogleVendors = !1,
        this.hasGenVendors = !1,
        this.iabAccInit = !1,
        this._displayNull = "display: '';",
        this.ARIA_LABEL_ATTRIBUTE = "aria-label",
        this.googleSearchSelectors = {
            vendorAccBtn: "#ot-addtl-venlst #Adtl-IAB",
            name: "name",
            accId: ".ot-adtlv-acc",
            selectAllEvntHndlr: "#ot-selall-adtlven-handler",
            venListId: "#ot-addtl-venlst",
            ctgl: ".ot-ven-adtlctgl"
        },
        this.genVendorSearchSelectors = {
            vendorAccBtn: "#ot-gn-venlst #Gn-",
            name: "Name",
            accId: ".ot-gv-acc",
            selectAllEvntHndlr: "#ot-selall-gnven-handler",
            venListId: "#ot-gn-venlst",
            ctgl: ".ot-ven-gvctgl"
        }
    }
    var Dn, Hn = (Fn.prototype.updateGtmMacros = function(e) {
        void 0 === e && (e = !0);
        var n = [];
        Ht.groupsConsent.forEach(function(e) {
            var t = e.replace(":1", "")
              , o = Xt.getGrpStatus(Xt.getGroupById(t)).toLowerCase() === De;
            Bt.endsWith(e, ":1") && (hn.canSoftOptInInsertForGroup(t) || o) && n.push(t)
        }),
        Ht.hostsConsent.forEach(function(e) {
            Bt.endsWith(e, ":1") && n.push(e.replace(":1", ""))
        }),
        Ht.showGeneralVendors && Nt.GenVenOptOut && Nt.GeneralVendors.forEach(function(e) {
            Ht.genVendorsConsent[e.VendorCustomId] && (Ht.softOptInGenVendors.includes(e.VendorCustomId) && mo.isLandingPage() || n.push(e.VendorCustomId))
        }),
        Ht.vsIsActiveAndOptOut && Ht.getVendorsInDomain().forEach(function(e) {
            Ht.vsConsent.get(e.CustomVendorServiceId) && n.push(e.CustomVendorServiceId)
        });
        var t, o, r = "," + Bt.arrToStr(n) + ",";
        Nt.GoogleConsent.GCEnable && this.updateGCMTags(n),
        window.OnetrustActiveGroups = r,
        window.OptanonActiveGroups = r,
        Ot.otDataLayer.ignore || void 0 === this._window[Ot.otDataLayer.name] || this._window[Ot.otDataLayer.name].constructor !== Array ? !Ot.otDataLayer.ignore && Ot.otDataLayer.name && (this._window[Ot.otDataLayer.name] = [{
            event: "OneTrustLoaded",
            OnetrustActiveGroups: r
        }, {
            event: "OptanonLoaded",
            OptanonActiveGroups: r
        }]) : (this._window[Ot.otDataLayer.name].push({
            event: "OneTrustLoaded",
            OnetrustActiveGroups: r
        }),
        this._window[Ot.otDataLayer.name].push({
            event: "OptanonLoaded",
            OptanonActiveGroups: r
        })),
        !e && Ot.gtmUpdatedinStub || (t = new CustomEvent("consent.onetrust",{
            detail: n
        }));
        var i = Vt.readCookieParam(Ee.OPTANON_CONSENT, "groups");
        !Ht.fireOnetrustGrp && i && !e && Ot.gtmUpdatedinStub || (Ht.fireOnetrustGrp = !1,
        !Ot.otDataLayer.ignore && this._window[Ot.otDataLayer.name] && this._window[Ot.otDataLayer.name].constructor === Array && this._window[Ot.otDataLayer.name].push({
            event: "OneTrustGroupsUpdated",
            OnetrustActiveGroups: r
        }),
        o = new CustomEvent("OneTrustGroupsUpdated",{
            detail: n
        })),
        setTimeout(function() {
            t && window.dispatchEvent(t),
            o && window.dispatchEvent(o)
        })
    }
    ,
    Fn.prototype.updateGCMTags = function(e) {
        var t = {};
        if (this.canUpdateGCMCategories()) {
            if (Nt.GoogleConsent.GCAdStorage !== ct) {
                var o = e.includes(Nt.GoogleConsent.GCAdStorage) ? ve.granted : ve.denied;
                t[ye.ad_storage] = o
            }
            if (Nt.GoogleConsent.GCAnalyticsStorage !== ct) {
                var n = e.includes(Nt.GoogleConsent.GCAnalyticsStorage) ? ve.granted : ve.denied;
                t[ye.analytics_storage] = n
            }
            if (Nt.GoogleConsent.GCFunctionalityStorage !== ct) {
                var r = e.includes(Nt.GoogleConsent.GCFunctionalityStorage) ? ve.granted : ve.denied;
                t[ye.functionality_storage] = r
            }
            if (Nt.GoogleConsent.GCPersonalizationStorage !== ct) {
                var i = e.includes(Nt.GoogleConsent.GCPersonalizationStorage) ? ve.granted : ve.denied;
                t[ye.personalization_storage] = i
            }
            if (Nt.GoogleConsent.GCSecurityStorage !== ct) {
                var s = e.includes(Nt.GoogleConsent.GCSecurityStorage) ? ve.granted : ve.denied;
                t[ye.security_storage] = s
            }
        }
        var a = Vt.getCookie(Ee.ALERT_BOX_CLOSED)
          , l = Ot.getRegionRule().Global;
        if ("function" != typeof window.gtag) {
            var c = this._window;
            window.gtag = function(e, t, o) {
                Ot.otDataLayer.ignore || (c[Ot.otDataLayer.name] ? c[Ot.otDataLayer.name].push(arguments) : c[Ot.otDataLayer.name] = [arguments])
            }
        }
        "function" == typeof window.gtag && (Ot.gcmDevIdSet || (window.gtag(pe.set, "developer_id.dYWJhMj", !0),
        Ot.gcmDevIdSet = !0),
        a && (l || (t[ye.region] = Ot.gcmCountries),
        0 !== Object.keys(t).length && window.gtag(pe.consent, ge.update, t)))
    }
    ,
    Fn.prototype.canUpdateGCMCategories = function() {
        return Nt.GoogleConsent.GCAdStorage !== ct || Nt.GoogleConsent.GCAnalyticsStorage !== ct || Nt.GoogleConsent.GCFunctionalityStorage !== ct || Nt.GoogleConsent.GCPersonalizationStorage !== ct || Nt.GoogleConsent.GCSecurityStorage !== ct
    }
    ,
    Fn);
    function Fn() {
        this._window = window
    }
    var Rn, qn = "Banner", Mn = "Preference Center", Un = "API", jn = "Close", zn = "Allow All", Kn = "Reject All", Wn = "Confirm", Jn = "Confirm", Yn = "Continue without Accepting", Xn = (Qn.prototype.showConsentNotice = function() {
        switch (!Nt.NoBanner || Nt.ForceConsent ? qt(".onetrust-pc-dark-filter").removeClass("ot-hide") : qt(".onetrust-pc-dark-filter").addClass("ot-hide"),
        qt("#onetrust-pc-sdk").removeClass("ot-hide"),
        Ot.pcName) {
        case rt:
            qt("#onetrust-pc-sdk").el[0].classList.contains("ot-animated") || qt("#onetrust-pc-sdk").addClass("ot-animated");
            var e = Nt.PreferenceCenterPosition
              , t = Nt.useRTL
              , o = t ? "right" : "left"
              , n = t ? "left" : "right";
            qt("#onetrust-pc-sdk").el[0].classList.contains("ot-slide-out-" + ("right" === e ? n : o)) && qt("#onetrust-pc-sdk").removeClass("ot-slide-out-" + ("right" === e ? n : o)),
            qt("#onetrust-pc-sdk").addClass("ot-slide-in-" + ("right" === e ? n : o))
        }
        Sn.setAllowAllButton(),
        mn.setPCFocus(mn.getPCElements()),
        Nt.NoBanner && Nt.ScrollCloseBanner || this.pcHasScroll()
    }
    ,
    Qn.prototype.hideConsentNoticeV2 = function() {
        if (0 !== qt(this.ONETRUST_PC_SDK).length) {
            if (It.isV2Template && this.closePCText(),
            Nt.ForceConsent && !Mt.isCookiePolicyPage(Nt.AlertNoticeText) && !Qt.isAlertBoxClosedAndValid() && Nt.ShowAlertNotice ? qt("" + this.ONETRUST_PC_DARK_FILTER).css("z-index: 2147483645;").show() : qt("" + this.ONETRUST_PC_DARK_FILTER).fadeOut(Nt.PCLayout.Panel ? 500 : 400),
            Nt.PCLayout.Panel) {
                var e = Nt.PreferenceCenterPosition
                  , t = Nt.useRTL
                  , o = t ? "right" : "left"
                  , n = t ? "left" : "right";
                qt("" + this.ONETRUST_PC_SDK).removeClass("ot-slide-in-" + ("right" === e ? n : o)),
                qt("" + this.ONETRUST_PC_SDK).addClass("ot-slide-out-" + ("right" === e ? n : o))
            }
            if (qt("" + this.ONETRUST_PC_SDK).fadeOut(Nt.PCLayout.Panel ? 500 : 400),
            Ht.isPCVisible = !1,
            (!Nt.NoBanner || !Nt.ScrollCloseBanner) && this.bodyStyleChanged) {
                var r = qt("html").el[0]
                  , i = qt("body").el[0];
                this.htmlStyleProp ? Lt(r, this.htmlStyleProp, !1) : r.removeAttribute("style"),
                this.bodyStyleProp ? Lt(i, this.bodyStyleProp, !1) : i.removeAttribute("style"),
                this.bodyStyleChanged = !1
            }
            if (Ht.pcLayer = _.Banner,
            Ht.pcSource || Qt.isAlertBoxClosedAndValid())
                Ht.pcSource ? (Ht.pcSource.focus(),
                Ht.pcSource = null) : Nt.BInitialFocus ? Mt.resetFocusToBody() : this.setFocusOnPage();
            else {
                var s = qt("#onetrust-banner-sdk #onetrust-pc-btn-handler").el[0];
                s && s.focus()
            }
        } else
            this.setFocusOnPage()
    }
    ,
    Qn.prototype.setFocusOnPage = function() {
        var e = document.querySelectorAll('button, a, input, select, textarea, [tabindex]:not([tabindex="-1"])');
        Ht.isKeyboardUser && e.length && e[0].focus()
    }
    ,
    Qn.prototype.closePCText = function() {
        var e = document.querySelector("#onetrust-pc-sdk span[aria-live]")
          , t = Nt.AboutCookiesText;
        e.innerText = t + " " + Nt.pcDialogClose
    }
    ,
    Qn.prototype.pcHasScroll = function() {
        var e = qt(Kt.P_Grp_Container).el[0] || qt("#onetrust-pc-sdk " + Kt.P_Content).el[0];
        if (e.scrollHeight > e.clientHeight) {
            this.bodyStyleChanged = !0;
            var t = qt("body");
            t.length && (this.bodyStyleProp = t.el[0].style.cssText,
            this.htmlStyleProp = qt("html").el[0].style.cssText,
            Lt(qt("html").el[0], "overflow: hidden;", !0),
            Lt(qt("body").el[0], "overflow: hidden;", !0))
        }
    }
    ,
    Qn.prototype.checkIfPcSdkContainerExist = function() {
        return !qt("#onetrust-pc-sdk").length
    }
    ,
    Qn);
    function Qn() {
        this.ONETRUST_PC_SDK = "#onetrust-pc-sdk",
        this.ONETRUST_PC_DARK_FILTER = ".onetrust-pc-dark-filter",
        this.bodyStyleChanged = !1
    }
    var $n, Zn = (er.prototype.init = function() {
        this.insertHtml(),
        this.insertCss(),
        this.showNty(),
        this.initHandler()
    }
    ,
    er.prototype.getContent = function() {
        return c(this, void 0, void 0, function() {
            return C(this, function(e) {
                return [2, dn.getSyncNtfyContent().then(function(e) {
                    Ht.syncNtfyGrp = {
                        name: e.name,
                        html: atob(e.html),
                        css: e.css
                    }
                })]
            })
        })
    }
    ,
    er.prototype.insertHtml = function() {
        function e(e) {
            return t.querySelector(e)
        }
        this.removeHtml();
        var t = document.createDocumentFragment()
          , o = document.createElement("div");
        qt(o).html(Ht.syncNtfyGrp.html);
        var n = o.querySelector(this.El);
        Nt.BannerRelativeFontSizesToggle && qt(n).addClass("otRelFont"),
        Nt.useRTL && qt(n).attr("dir", "rtl"),
        qt(t).append(n);
        var r = Nt.NtfyConfig;
        this.initHtml("Sync", r.Sync, e, t.querySelector(this.El)),
        r.ShowCS ? qt(e(".ot-pc-handler")).html(r.CSTxt) : (qt(n).addClass("ot-hide-csbtn"),
        e(".ot-sync-btncntr").parentElement.removeChild(e(".ot-sync-btncntr")));
        var i = document.createElement("div");
        qt(i).append(t),
        qt("#onetrust-consent-sdk").append(i.firstChild)
    }
    ,
    er.prototype.initHandler = function() {
        qt(this.El + " .ot-sync-close-handler").on("click", function() {
            return $n.close()
        })
    }
    ,
    er.prototype.showNty = function() {
        var e = qt(this.El);
        e.css("bottom: -300px;"),
        e.animate({
            bottom: "1em;"
        }, 1e3),
        setTimeout(function() {
            e.css("bottom: 1rem;")
        }, 1e3),
        e.focus()
    }
    ,
    er.prototype.changeState = function() {
        setTimeout(function() {
            $n.refreshState()
        }, 1500)
    }
    ,
    er.prototype.refreshState = function() {
        function e(e) {
            return t.querySelector(e)
        }
        var t = qt(this.El).el[0];
        t.classList.add("ot-nty-complete"),
        t.classList.remove("ot-nty-sync");
        var o = Nt.NtfyConfig;
        this.initHtml("Complete", o.Complete, e, t),
        o.ShowCS && ("LINK" === o.CSType && qt(e(".ot-pc-handler")).addClass("ot-pc-link"),
        qt(".ot-sync-btncntr").show("inline-block"),
        this.alignContent(),
        qt(window).on("resize", function() {
            return $n.resizeEvent
        })),
        setTimeout(function() {
            $n.close()
        }, 1e3 * Nt.NtfyConfig.NtfyDuration)
    }
    ,
    er.prototype.insertCss = function() {
        var e = document.getElementById("onetrust-style");
        e.innerHTML += Ht.syncNtfyGrp.css,
        e.innerHTML += this.addCustomStyles()
    }
    ,
    er.prototype.addCustomStyles = function() {
        var e = Nt.NtfyConfig
          , t = e.Sync
          , o = e.Complete
          , n = e.CSButton
          , r = e.CSLink;
        return "\n        #onetrust-consent-sdk #ot-sync-ntfy.ot-nty-sync {\n            background-color: " + t.BgColor + ";\n            border: 1px solid " + t.BdrColor + ";\n        }\n        #onetrust-consent-sdk #ot-sync-ntfy .ot-sync-refresh>g {\n            fill: " + t.IconBgColor + ";\n        }\n        #onetrust-consent-sdk #ot-sync-ntfy.ot-nty-sync #ot-sync-title {\n            text-align: " + t.TitleAlign + ";\n            color: " + t.TitleColor + ";\n        }\n        #onetrust-consent-sdk #ot-sync-ntfy.ot-nty-sync .ot-sync-desc  {\n            text-align: " + t.DescAlign + ";\n            color: " + t.DescColor + "; \n        }\n        #onetrust-consent-sdk #ot-sync-ntfy.ot-nty-complete {\n            background-color: " + o.BgColor + ";\n            border: 1px solid " + o.BdrColor + ";\n        }\n        #onetrust-consent-sdk #ot-sync-ntfy .ot-sync-check>g {\n            fill: " + o.IconBgColor + ";\n        }\n        #onetrust-consent-sdk #ot-sync-ntfy.ot-nty-complete #ot-sync-title {\n            text-align: " + o.TitleAlign + ";\n            color: " + o.TitleColor + ";\n        }\n        #onetrust-consent-sdk #ot-sync-ntfy.ot-nty-complete .ot-sync-desc  {\n            text-align: " + o.DescAlign + ";\n            color: " + o.DescColor + "; \n        }\n        " + ("BUTTON" === e.CSType ? "\n        #onetrust-consent-sdk #ot-sync-ntfy .ot-pc-handler {\n            background-color: " + n.BgColor + ";\n            border: 1px solid " + n.BdrColor + ";\n            color: " + n.Color + ";\n            text-align: " + n.Align + ";\n        }" : " #onetrust-consent-sdk #ot-sync-ntfy .ot-pc-handler.ot-pc-link {\n            color: " + r.Color + ";\n            text-align: " + r.Align + ";\n        }") + "\n        "
    }
    ,
    er.prototype.initHtml = function(e, t, o, n) {
        var r = "Sync" === e ? ".ot-sync-refresh" : ".ot-sync-check"
          , i = "Complete" === e ? ".ot-sync-refresh" : ".ot-sync-check";
        t.ShowIcon ? (qt(o(r)).show(),
        qt(o(i)).hide(),
        qt(o(".ot-sync-icon")).show("inline-block"),
        n.classList.remove("ot-hide-icon")) : (qt(o(".ot-sync-icon")).hide(),
        n.classList.add("ot-hide-icon")),
        t.Title ? qt(o("#ot-sync-title")).html(t.Title) : qt(o("#ot-sync-title")).hide(),
        t.Desc ? qt(o(".ot-sync-desc")).html(t.Desc) : qt(o(".ot-sync-desc")).hide(),
        t.ShowClose ? (qt(o(".ot-sync-close-handler")).show("inline-block"),
        qt(o(".ot-close-icon")).attr("aria-label", t.CloseAria),
        n.classList.remove("ot-hide-close")) : (qt(o(".ot-sync-close-handler")).hide(),
        n.classList.add("ot-hide-close"))
    }
    ,
    er.prototype.close = function() {
        this.hideSyncNtfy(),
        Mt.resetFocusToBody()
    }
    ,
    er.prototype.hideSyncNtfy = function() {
        Nt.NtfyConfig.ShowCS && window.removeEventListener("resize", $n.resizeEvent),
        qt("#ot-sync-ntfy").fadeOut(400)
    }
    ,
    er.prototype.removeHtml = function() {
        var e = qt(this.El).el;
        e && Bt.removeChild(e)
    }
    ,
    er.prototype.alignContent = function() {
        qt(".ot-sync-btncntr").el[0].clientHeight > qt(".ot-sync-titlecntr").el[0].clientHeight && (qt(".ot-sync-titlecntr").addClass("ot-pos-abs"),
        qt(".ot-sync-btncntr").addClass("ot-pos-rel"))
    }
    ,
    er.prototype.resizeEvent = function() {
        window.innerWidth <= 896 && $n.alignContent()
    }
    ,
    er);
    function er() {
        this.El = "#ot-sync-ntfy"
    }
    var tr, or = (nr.prototype.toggleVendorConsent = function(e, t) {
        void 0 === e && (e = []),
        void 0 === t && (t = null),
        e.length || (e = Ht.oneTrustIABConsent.vendors),
        e.forEach(function(e) {
            var t = e.split(":")
              , o = t[0]
              , n = t[1]
              , r = qt(Kt.P_Vendor_Container + " ." + Kt.P_Ven_Ctgl + ' [vendorid="' + o + '"]').el[0];
            r && Bt.setCheckedAttribute("", r, "true" === n)
        });
        var o = qt("#onetrust-pc-sdk #select-all-vendor-groups-handler").el[0];
        if (o) {
            var n = Bt.getActiveIdArray(Bt.distinctArray(e));
            null === t && (t = n.length === e.length),
            t || 0 === n.length ? o.parentElement.classList.remove(Wt.P_Line_Through) : o.parentElement.classList.add(Wt.P_Line_Through),
            Bt.setCheckedAttribute("", o, t)
        }
    }
    ,
    nr.prototype.toggleVendorLi = function(e, t) {
        void 0 === e && (e = []),
        void 0 === t && (t = null),
        e.length || (e = Ht.oneTrustIABConsent.legIntVendors),
        e.forEach(function(e) {
            var t = e.split(":")
              , o = t[0]
              , n = t[1]
              , r = qt(Kt.P_Vendor_Container + " ." + Kt.P_Ven_Ltgl + ' [leg-vendorid="' + o + '"]').el[0];
            r && Bt.setCheckedAttribute("", r, "true" === n)
        });
        var o = qt("#onetrust-pc-sdk #select-all-vendor-leg-handler").el[0];
        if (o) {
            var n = Bt.getActiveIdArray(Bt.distinctArray(e));
            null === t && (t = n.length === e.length),
            t || 0 === n.length ? o.parentElement.classList.remove(Wt.P_Line_Through) : o.parentElement.classList.add(Wt.P_Line_Through),
            Bt.setCheckedAttribute("", o, t)
        }
    }
    ,
    nr.prototype.updateVendorLegBtns = function(e) {
        void 0 === e && (e = []),
        e.length || (e = Ht.oneTrustIABConsent.legIntVendors),
        e.forEach(function(e) {
            var t = e.split(":")
              , o = t[0]
              , n = t[1]
              , r = qt(Kt.P_Vendor_Container + ' .ot-leg-btn-container[data-group-id="' + o + '"]').el[0];
            r && Sn.updateLegIntBtnElement(r, "true" === n)
        })
    }
    ,
    nr);
    function nr() {}
    var rr, ir = (sr.prototype.setFilterList = function(t) {
        var o = this
          , n = qt("#onetrust-pc-sdk " + Kt.P_Fltr_Modal + " " + Kt.P_Fltr_Option).el[0].cloneNode(!0);
        qt("#onetrust-pc-sdk " + Kt.P_Fltr_Modal + " " + Kt.P_Fltr_Options).html(""),
        (It.isV2Template || Nt.PCLayout.Popup) && qt("#onetrust-pc-sdk #filter-cancel-handler").html(Nt.PCenterCancelFiltersText || "Cancel"),
        !It.isV2Template && Nt.PCLayout.Popup || (qt("#onetrust-pc-sdk " + Kt.P_Clr_Fltr_Txt).html(Nt.PCenterClearFiltersText),
        qt("#filter-btn-handler").el[0].setAttribute("aria-label", Nt.PCenterFilterText)),
        qt("#onetrust-pc-sdk #filter-apply-handler").html(Nt.PCenterApplyFiltersText),
        t ? Ot.consentableGrps.forEach(function(e) {
            (Ht.cookieListType === X.GenVen || Ht.cookieListType === X.HostAndGenVen ? e.Hosts.length || e.FirstPartyCookies.length || e.GeneralVendorsIds && e.GeneralVendorsIds.length : e.Hosts.length || e.FirstPartyCookies.length) && o.filterGroupOptionSetter(n, e, t)
        }) : Ot.iabGrps.forEach(function(e) {
            o.filterGroupOptionSetter(n, e, t)
        })
    }
    ,
    sr.prototype.setFilterListByGroup = function(e, t) {
        var o = this;
        if (!e || e.length <= 0)
            qt("#onetrust-pc-sdk " + Kt.P_Fltr_Modal + " " + Kt.P_Fltr_Options).html("");
        else {
            var n = qt("#onetrust-pc-sdk " + Kt.P_Fltr_Modal + " " + Kt.P_Fltr_Option).el[0].cloneNode(!0);
            qt("#onetrust-pc-sdk " + Kt.P_Fltr_Modal + " " + Kt.P_Fltr_Options).html(""),
            (It.isV2Template || Nt.PCLayout.Popup) && qt("#onetrust-pc-sdk #filter-cancel-handler").html(Nt.PCenterCancelFiltersText || "Cancel"),
            !It.isV2Template && Nt.PCLayout.Popup || (qt("#onetrust-pc-sdk " + Kt.P_Clr_Fltr_Txt).html(Nt.PCenterClearFiltersText),
            qt("#filter-btn-handler").el[0].setAttribute("aria-label", Nt.PCenterFilterText)),
            qt("#onetrust-pc-sdk #filter-apply-handler").html(Nt.PCenterApplyFiltersText),
            e.forEach(function(e) {
                o.filterGroupOptionSetter(n, e, t)
            })
        }
    }
    ,
    sr.prototype.filterGroupOptionSetter = function(e, t, o) {
        var n = t.CustomGroupId
          , r = n + "-filter"
          , i = e.cloneNode(!0);
        qt(Kt.P_Fltr_Modal + " " + Kt.P_Fltr_Options).append(i),
        qt(i.querySelector("input")).attr("id", r),
        qt(i.querySelector("label")).attr("for", r),
        It.isV2Template ? qt(i.querySelector(Kt.P_Label_Txt)).html(t.GroupName) : qt(i.querySelector("label span")).html(t.GroupName),
        qt(i.querySelector("input")).attr(o ? "data-optanongroupid" : "data-purposeid", n)
    }
    ,
    sr);
    function sr() {
        this.bodyScrollProp = "",
        this.htmlScrollProp = "",
        this.ONETRUST_PC_SDK = "#onetrust-pc-sdk",
        this.ONETRUST_PC_DARK_FILTER = ".onetrust-pc-dark-filter"
    }
    var ar, lr = (cr.prototype.initialiseCssReferences = function() {
        var e, t = "";
        document.getElementById("onetrust-style") ? e = document.getElementById("onetrust-style") : ((e = document.createElement("style")).id = "onetrust-style",
        It.fp.CookieV2CSP && Ht.nonce && e.setAttribute("nonce", Ht.nonce)),
        hn.commonStyles && (t += hn.commonStyles),
        hn.bannerGroup && (t += hn.bannerGroup.css,
        It.fp.CookieV2SSR || (t += this.addCustomBannerCSS()),
        Nt.bannerCustomCSS && (t += Nt.bannerCustomCSS)),
        hn.preferenceCenterGroup && (t += hn.preferenceCenterGroup.css,
        t += this.addCustomPreferenceCenterCSS()),
        hn.cookieListGroup && (t += hn.cookieListGroup.css,
        t += this.addCustomCookieListCSS()),
        Nt.cookiePersistentLogo && !Nt.cookiePersistentLogo.includes("ot_guard_logo.svg") && (t += ".ot-floating-button__front{background-image:url('" + Nt.cookiePersistentLogo + "')}"),
        this.processedCSS = t,
        Ot.ignoreInjectingHtmlCss || (e.textContent = t,
        qt(document.head).append(e))
    }
    ,
    cr);
    function cr() {
        this.processedCSS = "",
        this.addCustomBannerCSS = function() {
            var e = Nt.backgroundColor
              , t = Nt.buttonColor
              , o = Nt.textColor
              , n = Nt.buttonTextColor
              , r = Nt.bannerMPButtonColor
              , i = Nt.bannerMPButtonTextColor
              , s = Nt.bannerAccordionBackgroundColor
              , a = Nt.BSaveBtnColor
              , l = Nt.BCategoryContainerColor
              , c = Nt.BLineBreakColor
              , d = Nt.BCategoryStyleColor
              , u = Nt.bannerLinksTextColor
              , p = Nt.BFocusBorderColor
              , h = "\n        " + (Ot.bannerName === Qe ? e ? "#onetrust-consent-sdk #onetrust-banner-sdk .ot-sdk-container {\n                    background-color: " + e + ";}" : "" : e ? "#onetrust-consent-sdk #onetrust-banner-sdk {background-color: " + e + ";}" : "") + "\n            " + (o ? "#onetrust-consent-sdk #onetrust-policy-title,\n                    #onetrust-consent-sdk #onetrust-policy-text,\n                    #onetrust-consent-sdk .ot-b-addl-desc,\n                    #onetrust-consent-sdk .ot-dpd-desc,\n                    #onetrust-consent-sdk .ot-dpd-title,\n                    #onetrust-consent-sdk #onetrust-policy-text *:not(.onetrust-vendors-list-handler),\n                    #onetrust-consent-sdk .ot-dpd-desc *:not(.onetrust-vendors-list-handler),\n                    #onetrust-consent-sdk #onetrust-banner-sdk #banner-options *,\n                    #onetrust-banner-sdk .ot-cat-header {\n                        color: " + o + ";\n                    }" : "") + "\n            " + (s ? "#onetrust-consent-sdk #onetrust-banner-sdk .banner-option-details {\n                    background-color: " + s + ";}" : "") + "\n            " + (u ? " #onetrust-consent-sdk #onetrust-banner-sdk a[href],\n                    #onetrust-consent-sdk #onetrust-banner-sdk a[href] font,\n                    #onetrust-consent-sdk #onetrust-banner-sdk .ot-link-btn\n                        {\n                            color: " + u + ";\n                        }" : "");
            if ((t || n) && (h += "#onetrust-consent-sdk #onetrust-accept-btn-handler,\n                         #onetrust-banner-sdk #onetrust-reject-all-handler {\n                            " + (t ? "background-color: " + t + ";border-color: " + t + ";" : "") + "\n                " + (n ? "color: " + n + ";" : "") + "\n            }"),
            p && (h += "\n            #onetrust-consent-sdk #onetrust-banner-sdk *:focus,\n            #onetrust-consent-sdk #onetrust-banner-sdk:focus {\n               outline-color: " + p + ";\n               outline-width: 1px;\n            }"),
            (i || r) && (h += "\n            #onetrust-consent-sdk #onetrust-pc-btn-handler,\n            #onetrust-consent-sdk #onetrust-pc-btn-handler.cookie-setting-link {\n                " + (i ? "color: " + i + "; border-color: " + i + ";" : "") + "\n                background-color: \n                " + (r && !Nt.BannerSettingsButtonDisplayLink ? r : e) + ";\n            }"),
            Ot.bannerName === et) {
                var g = void 0
                  , C = void 0
                  , y = void 0
                  , f = void 0
                  , v = void 0;
                a && (g = "color: " + n + ";border-color: " + n + ";background-color: " + a + ";"),
                l && (C = "background-color: " + l + ";"),
                c && (y = "border-color: " + c + ";"),
                d && (f = "background-color: " + d + ";",
                v = "border-color: " + d + ";"),
                p && (h += "\n                #onetrust-consent-sdk #onetrust-banner-sdk .ot-tgl input:focus+.ot-switch .ot-switch-nob,\n                #onetrust-consent-sdk #onetrust-banner-sdk .ot-chkbox input:focus + label::before {\n                    outline-color: " + p + ";\n                    outline-width: 1px;\n                }"),
                h += "#onetrust-banner-sdk .ot-bnr-save-handler {" + g + "}#onetrust-banner-sdk .ot-cat-lst {" + C + "}#onetrust-banner-sdk .ot-cat-bdr {" + y + "}#onetrust-banner-sdk .ot-tgl input:checked+.ot-switch .ot-switch-nob:before,#onetrust-banner-sdk .ot-chkbox input:checked~label::before {" + f + "}#onetrust-banner-sdk .ot-chkbox label::before,#onetrust-banner-sdk .ot-tgl input:checked+.ot-switch .ot-switch-nob {" + v + "}#onetrust-banner-sdk #onetrust-pc-btn-handler.cookie-setting-link {background: inherit}"
            }
            return Nt.BCloseButtonType === de.Link && (h += "#onetrust-banner-sdk.ot-close-btn-link .banner-close-button {color: " + Nt.BContinueColor + "}"),
            h
        }
        ,
        this.addCustomPreferenceCenterCSS = function() {
            var e = Nt.pcBackgroundColor
              , t = Nt.pcButtonColor
              , o = Nt.pcTextColor
              , n = Nt.pcButtonTextColor
              , r = Nt.pcLinksTextColor
              , i = Nt.PCenterEnableAccordion
              , s = Nt.pcAccordionBackgroundColor
              , a = Nt.pcMenuColor
              , l = Nt.pcMenuHighLightColor
              , c = Nt.pcLegIntButtonColor
              , d = Nt.pcLegIntButtonTextColor
              , u = Nt.PCFocusBorderColor
              , p = "\n            " + (e ? (Ot.pcName === nt ? "#onetrust-consent-sdk #onetrust-pc-sdk .group-parent-container,\n                        #onetrust-consent-sdk #onetrust-pc-sdk .manage-pc-container,\n                        #onetrust-pc-sdk " + Kt.P_Vendor_List : "#onetrust-consent-sdk #onetrust-pc-sdk") + ",\n                #onetrust-consent-sdk " + Kt.P_Search_Cntr + ",\n                " + (i && Ot.pcName === nt ? "#onetrust-consent-sdk #onetrust-pc-sdk .ot-accordion-layout" + Kt.P_Category_Item : "#onetrust-consent-sdk #onetrust-pc-sdk .ot-switch.ot-toggle") + ",\n                #onetrust-consent-sdk #onetrust-pc-sdk " + Kt.P_Tab_Grp_Hdr + " .checkbox,\n                #onetrust-consent-sdk #onetrust-pc-sdk " + Kt.P_Title + ":after\n                " + (It.isV2Template ? ",#onetrust-consent-sdk #onetrust-pc-sdk #ot-sel-blk,\n                        #onetrust-consent-sdk #onetrust-pc-sdk #ot-fltr-cnt,\n                        #onetrust-consent-sdk #onetrust-pc-sdk " + Kt.P_Triangle : "") + " {\n                    background-color: " + e + ";\n                }\n               " : "") + "\n            " + (o ? "#onetrust-consent-sdk #onetrust-pc-sdk h3,\n                #onetrust-consent-sdk #onetrust-pc-sdk h4,\n                #onetrust-consent-sdk #onetrust-pc-sdk h5,\n                #onetrust-consent-sdk #onetrust-pc-sdk h6,\n                #onetrust-consent-sdk #onetrust-pc-sdk p,\n                #onetrust-consent-sdk #onetrust-pc-sdk " + Kt.P_Vendor_Container + " " + Kt.P_Ven_Opts + " p,\n                #onetrust-consent-sdk #onetrust-pc-sdk " + Kt.P_Policy_Txt + ",\n                #onetrust-consent-sdk #onetrust-pc-sdk " + Kt.P_Title + ",\n                #onetrust-consent-sdk #onetrust-pc-sdk " + Kt.P_Li_Title + ",\n                #onetrust-consent-sdk #onetrust-pc-sdk " + Kt.P_Leg_Select_All + " span,\n                #onetrust-consent-sdk #onetrust-pc-sdk " + Kt.P_Host_Cntr + " " + Kt.P_Host_Info + ",\n                #onetrust-consent-sdk #onetrust-pc-sdk " + Kt.P_Fltr_Modal + " #modal-header,\n                #onetrust-consent-sdk #onetrust-pc-sdk .ot-checkbox label span,\n                #onetrust-consent-sdk #onetrust-pc-sdk " + Kt.P_Vendor_List + " " + Kt.P_Select_Cntr + " p,\n                #onetrust-consent-sdk #onetrust-pc-sdk " + Kt.P_Vendor_List + " " + Kt.P_Vendor_Title + ",\n                #onetrust-consent-sdk #onetrust-pc-sdk " + Kt.P_Vendor_List + " .back-btn-handler p,\n                #onetrust-consent-sdk #onetrust-pc-sdk " + Kt.P_Vendor_List + " " + Kt.P_Ven_Name + ",\n                #onetrust-consent-sdk #onetrust-pc-sdk " + Kt.P_Vendor_List + " " + Kt.P_Vendor_Container + " .consent-category,\n                #onetrust-consent-sdk #onetrust-pc-sdk .ot-leg-btn-container .ot-inactive-leg-btn,\n                #onetrust-consent-sdk #onetrust-pc-sdk .ot-label-status,\n                #onetrust-consent-sdk #onetrust-pc-sdk .ot-chkbox label span,\n                #onetrust-consent-sdk #onetrust-pc-sdk #clear-filters-handler \n                {\n                    color: " + o + ";\n                }" : "") + "\n            " + (r ? " #onetrust-consent-sdk #onetrust-pc-sdk .privacy-notice-link,\n                    #onetrust-consent-sdk #onetrust-pc-sdk .category-vendors-list-handler,\n                    #onetrust-consent-sdk #onetrust-pc-sdk .category-vendors-list-handler + a,\n                    #onetrust-consent-sdk #onetrust-pc-sdk .category-host-list-handler,\n                    #onetrust-consent-sdk #onetrust-pc-sdk " + Kt.P_Ven_Link + ",\n                    #onetrust-consent-sdk #onetrust-pc-sdk " + Kt.P_Host_Cntr + " " + Kt.P_Host_Title + " a,\n                    #onetrust-consent-sdk #onetrust-pc-sdk " + Kt.P_Host_Cntr + " " + Kt.P_Acc_Header + " " + Kt.P_Host_View_Cookies + ",\n                    #onetrust-consent-sdk #onetrust-pc-sdk " + Kt.P_Host_Cntr + " " + Kt.P_Host_Info + " a,\n                    #onetrust-consent-sdk #onetrust-pc-sdk " + Kt.P_Content + " " + Kt.P_Policy_Txt + " .ot-link-btn\n                    {\n                        color: " + r + ";\n                    }" : "") + "\n            #onetrust-consent-sdk #onetrust-pc-sdk .category-vendors-list-handler:hover { text-decoration: underline;}\n            " + (i && s ? "#onetrust-consent-sdk #onetrust-pc-sdk " + Kt.P_Acc_Container + Kt.P_Acc_Txt + ",\n            #onetrust-consent-sdk #onetrust-pc-sdk " + Kt.P_Acc_Txt + " " + Kt.P_Subgrp_Tgl_Cntr + " .ot-switch.ot-toggle\n             {\n                background-color: " + s + ";\n            }" : "") + "\n            " + (s ? " #onetrust-consent-sdk #onetrust-pc-sdk " + Kt.P_Host_Cntr + " " + Kt.P_Host_Info + ",\n                    " + (It.isV2Template ? "#onetrust-consent-sdk #onetrust-pc-sdk " + Kt.P_Acc_Txt + " .ot-ven-dets" : "#onetrust-consent-sdk #onetrust-pc-sdk " + Kt.P_Acc_Txt + " " + Kt.P_Ven_Opts) + "\n                            {\n                                background-color: " + s + ";\n                            }" : "") + "\n        ";
            return (t || n) && (p += "#onetrust-consent-sdk #onetrust-pc-sdk \n            button:not(#clear-filters-handler):not(.ot-close-icon):not(#filter-btn-handler):not(.ot-remove-objection-handler):not(.ot-obj-leg-btn-handler):not([aria-expanded]):not(.ot-link-btn),\n            #onetrust-consent-sdk #onetrust-pc-sdk .ot-leg-btn-container .ot-active-leg-btn {\n                " + (t ? "background-color: " + t + ";border-color: " + t + ";" : "") + "\n                " + (n ? "color: " + n + ";" : "") + "\n            }\n            #onetrust-consent-sdk #onetrust-pc-sdk ." + Kt.P_Active_Menu + " {\n                " + (t ? "border-color: " + t + ";" : "") + "\n            }\n            " + (Ot.pcName === nt ? "#onetrust-consent-sdk #onetrust-pc-sdk " + Kt.P_Category_Item + ",\n            #onetrust-consent-sdk #onetrust-pc-sdk.ot-leg-opt-out " + Kt.P_Li_Hdr + "{\n                border-color: " + t + ";\n            }" : "") + "\n            #onetrust-consent-sdk #onetrust-pc-sdk .ot-leg-btn-container .ot-remove-objection-handler{\n                background-color: transparent;\n                border: 1px solid transparent;\n            }\n            #onetrust-consent-sdk #onetrust-pc-sdk .ot-leg-btn-container .ot-inactive-leg-btn {\n                " + (c ? "background-color: " + c + ";" : "") + "\n                " + (d ? "color: " + d + "; border-color: " + d + ";" : "") + "\n            }\n            "),
            u && (p += '\n            #onetrust-consent-sdk #onetrust-pc-sdk .ot-tgl input:focus + .ot-switch, .ot-switch .ot-switch-nob, .ot-switch .ot-switch-nob:before,\n            #onetrust-pc-sdk .ot-checkbox input[type="checkbox"]:focus + label::before,\n            #onetrust-pc-sdk .ot-chkbox input[type="checkbox"]:focus + label::before {\n                outline-color: ' + u + ";\n                outline-width: 1px;\n            }\n            #onetrust-pc-sdk .ot-host-item > button:focus, #onetrust-pc-sdk .ot-ven-item > button:focus {\n                border: 1px solid " + u + ";\n            }\n            #onetrust-consent-sdk #onetrust-pc-sdk *:focus,\n            #onetrust-consent-sdk #onetrust-pc-sdk .ot-vlst-cntr > a:focus {\n               outline: 1px solid " + u + ";\n            }"),
            Nt.PCCloseButtonType === de.Link && (p += "#onetrust-pc-sdk.ot-close-btn-link .ot-close-icon {color: " + Nt.PCContinueColor + "}"),
            Ot.pcName === st && (a && (p += "#onetrust-consent-sdk #onetrust-pc-sdk .category-menu-switch-handler {\n                    background-color: " + a + "\n                }"),
            l && (p += "#onetrust-consent-sdk #onetrust-pc-sdk ." + Kt.P_Active_Menu + " {\n                    background-color: " + l + "\n                }")),
            !Nt.PCTemplateUpgrade && u && (p += '\n            #onetrust-pc-sdk input[type="checkbox"]:focus + .accordion-header,\n            #onetrust-pc-sdk .category-item .ot-switch.ot-toggle input:focus + .ot-switch-label,\n            #onetrust-pc-sdk .checkbox input:focus + label::after {\n                outline-color: ' + u + ";\n                outline-width: 1px;\n            }"),
            Nt.pcCustomCSS && (p += Nt.pcCustomCSS),
            p
        }
        ,
        this.addCustomCookieListCSS = function() {
            var e = Nt.CookiesV2NewCookiePolicy ? "-v2.ot-sdk-cookie-policy" : ""
              , t = "\n                " + (Nt.cookieListPrimaryColor ? "\n                    #ot-sdk-cookie-policy" + e + " h5,\n                    #ot-sdk-cookie-policy" + e + " h6,\n                    #ot-sdk-cookie-policy" + e + " li,\n                    #ot-sdk-cookie-policy" + e + " p,\n                    #ot-sdk-cookie-policy" + e + " a,\n                    #ot-sdk-cookie-policy" + e + " span,\n                    #ot-sdk-cookie-policy" + e + " td,\n                    #ot-sdk-cookie-policy" + e + " #cookie-policy-description {\n                        color: " + Nt.cookieListPrimaryColor + ";\n                    }" : "") + "\n                    " + (Nt.cookieListTableHeaderColor ? "#ot-sdk-cookie-policy" + e + " th {\n                        color: " + Nt.cookieListTableHeaderColor + ";\n                    }" : "") + "\n                    " + (Nt.cookieListGroupNameColor ? "#ot-sdk-cookie-policy" + e + " .ot-sdk-cookie-policy-group {\n                        color: " + Nt.cookieListGroupNameColor + ";\n                    }" : "") + "\n                    " + (Nt.cookieListTitleColor ? "\n                    #ot-sdk-cookie-policy" + e + " #cookie-policy-title {\n                            color: " + Nt.cookieListTitleColor + ";\n                        }\n                    " : "") + "\n            " + (e && Nt.CookieListTableHeaderBackgroundColor ? "\n                    #ot-sdk-cookie-policy" + e + " table th {\n                            background-color: " + Nt.CookieListTableHeaderBackgroundColor + ";\n                        }\n                    " : "") + "\n            ";
            return Nt.cookieListCustomCss && (t += Nt.cookieListCustomCss),
            t
        }
    }
    function dr() {
        return Nt.PCCategoryStyle === se.Toggle ? Vn.toggleEl.cloneNode(!0) : Vn.chkboxEl.cloneNode(!0)
    }
    var ur, pr = (hr.prototype.setHtmlTemplate = function(e) {
        ur.setInternalData(),
        ur.rootHtml = e,
        ur.cloneHtmlElements()
    }
    ,
    hr.prototype.getVendorListEle = function(e) {
        var t = document.createDocumentFragment()
          , r = document.createElement("div");
        r.classList.add("ot-vs-list");
        var i = Nt.VendorServiceConfig.PCVSExpandGroup;
        return e.forEach(function(e, t) {
            var o = "ot-vs-lst-id-" + t
              , n = ur.createVendor(e.groupRef, e, i, o);
            r.appendChild(n)
        }),
        t.appendChild(r),
        t
    }
    ,
    hr.prototype.insertVendorServiceHtml = function(e, t) {
        if (e && e.VendorServices && !(e.VendorServices.length <= 0) && t) {
            var o = document.createDocumentFragment();
            ur.setVendorContainer(o, e),
            ur.setVendorList(o, e),
            t.appendChild(o)
        }
    }
    ,
    hr.prototype.toggleVendorService = function(e, t, o, n) {
        var r = Xt.getGroupById(e)
          , i = Xt.getVSById(t);
        if (n = n || ur.getVendorInputElement(i.CustomVendorServiceId),
        ur.setVendorServiceState(n, i, o),
        o)
            ur.changeGroupState(r, o, ur.isToggle);
        else {
            var s = r
              , a = Xt.getParentByGrp(r);
            a && (s = a),
            ur.checkGroupChildrenState(s) || ur.changeGroupState(r, !1, ur.isToggle)
        }
    }
    ,
    hr.prototype.setVendorStateByGroup = function(e, t) {
        var o = e.VendorServices;
        if (Ht.showVendorService && o)
            for (var n = 0, r = o; n < r.length; n++) {
                var i = r[n]
                  , s = ur.getVendorInputElement(i.CustomVendorServiceId);
                ur.setVendorServiceState(s, i, t)
            }
    }
    ,
    hr.prototype.resetVendorUIState = function(e) {
        e.forEach(function(e, t) {
            var o = ur.getVendorInputElement(t);
            ur.changeVendorServiceUIState(o, e)
        })
    }
    ,
    hr.prototype.setVendorServiceState = function(e, t, o) {
        ur.changeVendorServiceState(t, o),
        ur.changeVendorServiceUIState(e, o);
        var n = o ? sn : an;
        Vo.triggerGoogleAnalyticsEvent(Go, n, t.ServiceName + ": " + t.CustomVendorServiceId)
    }
    ,
    hr.prototype.removeVSUITemplate = function(e) {
        var t = e.querySelector(".ot-vnd-serv");
        t && e.removeChild(t)
    }
    ,
    hr.prototype.consentAll = function(o) {
        Ht.getVendorsInDomain().forEach(function(e) {
            var t = o;
            o || (t = Xt.isAlwaysActiveGroup(e.groupRef)),
            ur.toggleVendorService(e.groupRef.CustomGroupId, e.CustomVendorServiceId, t || o)
        })
    }
    ,
    hr.prototype.cloneHtmlElements = function() {
        var e = ur.rootHtml.querySelector(".ot-vnd-serv");
        if (e) {
            var t = e.querySelector(".ot-vnd-serv-hdr-cntr")
              , o = e.querySelector(".ot-vnd-lst-cont")
              , n = o.querySelector(".ot-vnd-item")
              , r = n.querySelector(".ot-vnd-info");
            ur.vendorLabelContainerClone = t.cloneNode(!0),
            e.removeChild(t),
            ur.vendorInfoClone = r.cloneNode(!0),
            n.querySelector(".ot-vnd-info-cntr").removeChild(r),
            ur.vendorItemClone = n.cloneNode(!0),
            o.removeChild(n),
            ur.vendorListContainerClone = o.cloneNode(!0),
            e.removeChild(o),
            ur.vendorServMainContainerClone = e.cloneNode(!0),
            ur.rootHtml.removeChild(e)
        }
    }
    ,
    hr.prototype.setInternalData = function() {
        ur.isToggle = Nt.PCCategoryStyle === se.Toggle;
        var e = Nt.VendorServiceConfig;
        ur.stringTranslation = new Map,
        ur.stringTranslation.set("ServiceName", e.PCVSNameText || "ServiceName"),
        ur.stringTranslation.set("ParentCompany", e.PCVSParentCompanyText || "ParentCompany"),
        ur.stringTranslation.set("Address", e.PCVSAddressText || "Address"),
        ur.stringTranslation.set("DefaultCategoryName", e.PCVSDefaultCategoryText || "DefaultCategoryName"),
        ur.stringTranslation.set("Description", e.PCVSDefaultDescriptionText || "Description"),
        ur.stringTranslation.set("DPOEmail", e.PCVSDPOEmailText || "DPOEmail"),
        ur.stringTranslation.set("DPOLink", e.PCVSDPOLinkText || "DPOLink"),
        ur.stringTranslation.set("PrivacyPolicyLink", e.PCVSPrivacyPolicyLinkText || "PrivacyPolicyLink"),
        ur.stringTranslation.set("CookiePolicyLink", e.PCVSCookiePolicyLinkText || "CookiePolicyLink"),
        ur.stringTranslation.set("OptOutLink", e.PCVSOptOutLinkText || "OptOutLink"),
        ur.stringTranslation.set("LegalBasis", e.PCVSLegalBasisText || "LegalBasis")
    }
    ,
    hr.prototype.setVendorContainer = function(e, t) {
        var o = ur.vendorServMainContainerClone.cloneNode(!0);
        o.setAttribute("data-group-id", t.CustomGroupId);
        var n = ur.vendorLabelContainerClone.cloneNode(!0);
        n.querySelector(".ot-vnd-serv-hdr").innerHTML = Nt.VendorServiceConfig.PCVSListTitle,
        o.appendChild(n),
        e.appendChild(o)
    }
    ,
    hr.prototype.setVendorList = function(e, t) {
        for (var o = 0, n = t.VendorServices, r = n.length, i = e.querySelector(".ot-vnd-serv"), s = ur.vendorListContainerClone.cloneNode(), a = Nt.VendorServiceConfig.PCVSExpandCategory; o < r; o++) {
            var l = ur.createVendor(t, n[o], a);
            s.appendChild(l)
        }
        i.appendChild(s)
    }
    ,
    hr.prototype.createVendor = function(e, t, o, n) {
        var r = ur.vendorItemClone.cloneNode(!0);
        r.setAttribute("data-vnd-id", t.CustomVendorServiceId),
        ur.setExpandVendorList(r, o),
        ur.setVendorHeader(e, t, r, n);
        var i = r.querySelector(".ot-vnd-info-cntr");
        return ur.setVendorInfo(i, t),
        r
    }
    ,
    hr.prototype.setExpandVendorList = function(e, t) {
        e.querySelector("button").setAttribute("aria-expanded", "" + t)
    }
    ,
    hr.prototype.setVendorHeader = function(e, t, o, n) {
        var r = Nt.VendorServiceConfig.PCVSAlwaysActive
          , i = "always active" === Xt.getGrpStatus(e).toLowerCase()
          , s = o.querySelector(".ot-acc-hdr");
        i && s.classList.add("ot-always-active-group");
        var a = null;
        i && Nt.PCCategoryStyle === se.Toggle || (a = ur.setHeaderInputStyle(e, t, i, n));
        var l = ur.setHeaderText(t, s)
          , c = ur.setHeaderAccordionIcon();
        s.appendChild(l);
        var d = ur.getPositionForElement(Nt.PCAccordionStyle, ur.isToggle)
          , u = d.positionIcon
          , p = d.positionInput;
        if (a && s.insertAdjacentElement(p, a),
        i && r) {
            var h = ur.getAlwaysActiveElement();
            s.insertAdjacentElement("beforeend", h)
        }
        s.insertAdjacentElement(u, c)
    }
    ,
    hr.prototype.getPositionForElement = function(e, t) {
        var o = "beforeend"
          , n = "beforeend";
        return t && e === W.PlusMinus && (o = "afterbegin"),
        t || (n = "afterbegin"),
        {
            positionIcon: o,
            positionInput: n
        }
    }
    ,
    hr.prototype.setHeaderAccordionIcon = function() {
        return Nt.PCAccordionStyle === W.Caret ? Vn.arrowEl.cloneNode(!0) : Vn.plusMinusEl.cloneNode(!0)
    }
    ,
    hr.prototype.setHeaderText = function(e, t) {
        var o = t.querySelector(".ot-cat-header")
          , n = o.cloneNode();
        return t.removeChild(o),
        n.innerText = e.ServiceName,
        n
    }
    ,
    hr.prototype.setHeaderInputStyle = function(e, t, o, n) {
        if (!Nt.VendorServiceConfig.PCVSOptOut)
            return null;
        var r = Xt.checkIsActiveByDefault(e)
          , i = !1
          , s = Ht.vsConsent;
        i = s.has(t.CustomVendorServiceId) ? s.get(t.CustomVendorServiceId) : r;
        var a = dr();
        a.querySelector("input").classList.add("category-switch-handler");
        var l = a.querySelector("input")
          , c = t.CustomVendorServiceId
          , d = null != n ? n : "ot-vendor-id-" + c
          , u = "ot-vendor-header-id-" + c;
        qt(l).attr("id", d),
        qt(l).attr("name", d),
        qt(l).attr("aria-labelledby", u),
        qt(l).data("ot-vs-id", c),
        qt(l).data("optanongroupid", e.CustomGroupId),
        l.disabled = o,
        Bt.setCheckedAttribute(null, l, i);
        var p = ur.isToggle ? d : u;
        return qt(a.querySelector("label")).attr("for", p),
        qt(a.querySelector(".ot-label-txt")).html(t.ServiceName),
        a
    }
    ,
    hr.prototype.getAlwaysActiveElement = function() {
        var e = document.createElement("div");
        return e.classList.add("ot-always-active"),
        e.innerText = Nt.AlwaysActiveText,
        e
    }
    ,
    hr.prototype.setVendorInfo = function(e, t) {
        var o;
        for (o in t)
            if (!ur.skipVendorInfoKey(o, t)) {
                var n = t[o]
                  , r = ur.vendorInfoClone.cloneNode(!0);
                r.dataset.vndInfoKey = o + "-" + t.CustomVendorServiceId;
                var i = r.querySelector(".ot-vnd-lbl")
                  , s = r.querySelector(".ot-vnd-cnt");
                i.innerHTML = ur.getLocalizedString(o),
                s.innerHTML = n,
                e.appendChild(r)
            }
    }
    ,
    hr.prototype.skipVendorInfoKey = function(e, t) {
        return "VendorServiceId" === e || "DefaultCategoryId" === e || "ServiceName" === e || "groupRef" === e || "CustomVendorServiceId" === e || "PurposeId" === e || !t[e]
    }
    ,
    hr.prototype.getLocalizedString = function(e) {
        return ur.stringTranslation.has(e) ? ur.stringTranslation.get(e) : "DEFAULT"
    }
    ,
    hr.prototype.checkGroupChildrenState = function(e) {
        for (var t, o, n = 0, r = null != (t = e.SubGroups) ? t : []; n < r.length; n++) {
            var i = r[n];
            if (ur.checkGroupChildrenState(i))
                return !0
        }
        for (var s = 0, a = null != (o = e.VendorServices) ? o : []; s < a.length; s++) {
            var l = a[s];
            if (Ht.vsConsent.get(l.CustomVendorServiceId))
                return !0
        }
        return !1
    }
    ,
    hr.prototype.changeVendorServiceState = function(e, t) {
        Ht.vsConsent.set(e.CustomVendorServiceId, t)
    }
    ,
    hr.prototype.changeVendorServiceUIState = function(e, t) {
        e && (Bt.setCheckedAttribute(null, e, t),
        ur.isToggle && e.parentElement.querySelector(".ot-switch-nob").setAttribute("aria-checked", "" + t))
    }
    ,
    hr.prototype.changeGroupState = function(e, t, o) {
        var n = Xt.getParentByGrp(e);
        n && ur.changeGroupState(n, t, o),
        Sn.toggleGrpStatus(e, t),
        ur.updateGroupUIState(e.CustomGroupId, t, o)
    }
    ,
    hr.prototype.updateGroupUIState = function(e, t, o) {
        var n = document.querySelector("#ot-group-id-" + e);
        n && (Bt.setCheckedAttribute(null, n, t),
        o && n.parentElement.querySelector(".ot-switch-nob").setAttribute("aria-checked", "" + t))
    }
    ,
    hr.prototype.getVendorInputElement = function(e) {
        return document.getElementById("ot-vendor-id-" + e)
    }
    ,
    hr);
    function hr() {}
    var gr, Cr = (yr.prototype.insertPcHtml = function() {
        gr.jsonAddAboutCookies(Nt);
        var t = document.createDocumentFragment();
        if (hn.preferenceCenterGroup) {
            var e = document.createElement("div");
            qt(e).html(hn.preferenceCenterGroup.html);
            var o = e.querySelector("#onetrust-pc-sdk");
            /Chrome|Safari/i.test(navigator.userAgent) && /Google Inc|Apple Computer/i.test(navigator.vendor) || qt(o).addClass("ot-sdk-not-webkit"),
            Nt.useRTL && qt(o).attr("dir", "rtl"),
            Ot.legIntSettings.PAllowLI && "IAB2" === Ot.iabType && (qt(o).addClass("ot-leg-opt-out"),
            Ot.legIntSettings.PShowLegIntBtn && qt(o).addClass("ot-leg-btn")),
            Nt.BannerRelativeFontSizesToggle && qt(o).addClass("otRelFont"),
            Nt.PCShowConsentLabels && qt(o).addClass("ot-tgl-with-label"),
            (Nt.UseGoogleVendors || Ht.showGeneralVendors) && qt(o).addClass("ot-addtl-vendors"),
            "right" === Nt.PreferenceCenterPosition && qt(o).addClass(Nt.useRTL ? "right-rtl" : "right"),
            qt(t).append(o);
            var n = function(e) {
                return t.querySelector(e)
            }
              , r = function(e) {
                return t.querySelectorAll(e)
            }
              , i = qt(r(Kt.P_Close_Btn)).el;
            if (Nt.ShowPreferenceCenterCloseButton)
                for (Nt.CloseText || (Nt.CloseText = "Close Preference Center"),
                s = 0; s < i.length; s++)
                    Nt.PCCloseButtonType === de.Link && Nt.PCTemplateUpgrade ? (qt(i[s]).html(Nt.PCContinueText),
                    qt(o).addClass("ot-close-btn-link"),
                    qt(i[s]).el.removeAttribute("aria-label")) : qt(i[s]).el.setAttribute("aria-label", Nt.CloseText);
            else
                for (var s = 0; s < i.length; s++)
                    qt(i[s].parentElement).el.removeChild(i[s]);
            Nt.Language && Nt.Language.Culture && qt(n("#onetrust-pc-sdk")).attr("lang", Nt.Language.Culture);
            var a = n(Kt.P_Logo);
            if (a && Nt.optanonLogo) {
                var l = Mt.updateCorrectUrl(Nt.optanonLogo);
                Mt.checkMobileOfflineRequest(Mt.getBannerVersionUrl()) && (l = Bt.getRelativeURL(l, !0, !0)),
                qt(a).attr("style", 'background-image: url("' + l + '");\n                    background-position: ' + (Nt.useRTL ? "right" : "left") + ";"),
                Nt.PCLogoAria && qt(a).attr("aria-label", Nt.PCLogoAria)
            }
            if (Mt.insertFooterLogo(r(".ot-pc-footer-logo a")),
            qt(n(Kt.P_Title)).html(Nt.MainText),
            Nt.PCCloseButtonType === de.Link && Nt.PCTemplateUpgrade && Ot.pcName === st && qt(n(Kt.P_Title)).addClass("ot-pc-title-shrink"),
            qt(n(Io)).attr("aria-label", Nt.MainText),
            Ot.pcName === st && (qt(n(Kt.P_Privacy_Txt)).html(Nt.AboutCookiesText),
            qt(n(Kt.P_Privacy_Hdr)).html(Nt.AboutCookiesText)),
            qt(n(Kt.P_Policy_Txt)).html(Nt.MainInfoText),
            Nt.AboutText && qt(n(Kt.P_Policy_Txt)).html(qt(n(Kt.P_Policy_Txt)).html() + '\n                <br/><a href="' + Nt.AboutLink + '" class="privacy-notice-link" rel="noopener" target="_blank"\n                        aria-label="' + Nt.PCCookiePolicyLinkScreenReader + '">' + Nt.AboutText + "</a>"),
            Nt.PCenterVendorListLinkText) {
                var c = !Nt.IsIabEnabled && Ht.showGeneralVendors ? "ot-gv-list-handler" : "onetrust-vendors-list-handler";
                n(Kt.P_Policy_Txt).insertAdjacentHTML("beforeend", '<button class="ot-link-btn ' + c + '" aria-label="' + Nt.PCenterVendorListLinkAriaLabel + '">\n                ' + Nt.PCenterVendorListLinkText + "\n                </button>")
            }
            if (Nt.PCTemplateUpgrade && Nt.PCenterUserIdTitleText && Nt.IsConsentLoggingEnabled) {
                var d = Vt.readCookieParam(Ee.OPTANON_CONSENT, Te);
                if (n(Kt.P_Policy_Txt).insertAdjacentHTML("beforeend", '<div class="ot-userid-title"><span>' + Nt.PCenterUserIdTitleText + ": </span> " + d + "</div>"),
                Nt.PCenterUserIdDescriptionText && n(Kt.P_Policy_Txt).insertAdjacentHTML("beforeend", '<div class="ot-userid-desc">' + Nt.PCenterUserIdDescriptionText + "</div>"),
                Nt.PCenterUserIdTimestampTitleText) {
                    var u = Vt.getCookie(Ee.ALERT_BOX_CLOSED)
                      , p = u && Mt.getUTCFormattedDate(u)
                      , h = p || Nt.PCenterUserIdNotYetConsentedText;
                    n(Kt.P_Policy_Txt).insertAdjacentHTML("beforeend", '<div class="ot-userid-timestamp"><span>' + Nt.PCenterUserIdTimestampTitleText + ": </span> " + h + "</div>")
                }
            }
            Nt.ConfirmText.trim() ? qt(n("#accept-recommended-btn-handler")).html(Nt.ConfirmText) : n("#accept-recommended-btn-handler").parentElement.removeChild(n("#accept-recommended-btn-handler"));
            var g = r(".save-preference-btn-handler");
            for (s = 0; s < g.length; s++)
                qt(g[s]).html(Nt.AllowAllText);
            var C = r(".ot-pc-refuse-all-handler");
            if (Nt.PCenterShowRejectAllButton && Nt.PCenterRejectAllButtonText.trim())
                for (s = 0; s < C.length; s++)
                    qt(C[s]).html(Nt.PCenterRejectAllButtonText);
            else
                Bt.removeChild(C);
            if (n(Kt.P_Manage_Cookies_Txt) && qt(n(Kt.P_Manage_Cookies_Txt)).html(Nt.ManagePreferenceText),
            gr.initializePreferenceCenterGroups(n, t),
            !Nt.IsIabEnabled) {
                var y = n(Kt.P_Vendor_Container);
                y && y.parentElement.removeChild(y)
            }
            if (!Nt.showCookieList && !Ht.showGeneralVendors) {
                var f = n(Kt.P_Host_Cntr);
                f && f.parentElement.removeChild(f)
            }
        }
        var v = document.createElement("iframe");
        v.setAttribute("class", "ot-text-resize"),
        v.setAttribute("title", "onetrust-text-resize"),
        Lt(v, "position: absolute; top: -50000px; width: 100em;"),
        v.setAttribute(this._ariaHidden, "true"),
        qt(t.querySelector("#onetrust-pc-sdk")).append(v);
        var k = document.getElementById("onetrust-consent-sdk");
        qt(k).append(t),
        Ot.ignoreInjectingHtmlCss || qt(document.body).append(k),
        (Nt.showCookieList || Ht.showGeneralVendors) && En.InitializeHostList()
    }
    ,
    yr.prototype.setParentGroupName = function(e, t, o, n) {
        var r = e.querySelector(".category-header,.ot-cat-header,.category-menu-switch-handler>h3");
        qt(r).html(t),
        qt(r).attr("id", o),
        Ot.pcName === st && (e.querySelector(Kt.P_Category_Header).innerHTML = t,
        e.querySelector("" + Kt.P_Desc_Container).setAttribute("id", n),
        e.querySelector(".category-menu-switch-handler").setAttribute("aria-controls", n))
    }
    ,
    yr.prototype.setLegIntButton = function(e, t, o, n) {
        void 0 === o && (o = !1);
        var r = !0;
        -1 < Ht.vendors.selectedLegInt.indexOf(t.IabGrpId + ":false") && (r = !1);
        var i = Qt.generateLegIntButtonElements(r, t.OptanonGroupId);
        o ? n.insertAdjacentHTML("afterend", i) : e.insertAdjacentHTML("beforeend", i);
        var s = e.querySelector(".ot-remove-objection-handler");
        s && Lt(s, s.getAttribute("data-style"))
    }
    ,
    yr.prototype.setParentGroupDescription = function(e, t, o, n, r) {
        var i = Sn.safeFormattedGroupDescription(t)
          , s = e.querySelector("p:not(.ot-always-active)")
          , a = e.querySelector(Kt.P_Acc_Grp_Desc)
          , l = s || a;
        return -1 < Tt.indexOf(t.Type) && o.PCGrpDescType === G.Legal ? i = t.DescriptionLegal : l.classList.add("ot-category-desc"),
        Ot.legIntSettings.PAllowLI && !Ot.legIntSettings.PShowLegIntBtn && (t.SubGroups.some(function(e) {
            return e.HasLegIntOptOut
        }) || t.HasLegIntOptOut ? l.parentElement.classList.add("ot-leg-border-color") : Bt.removeChild(e.querySelector(Kt.P_Li_Hdr))),
        Ot.pcName !== st && l.setAttribute("id", n),
        qt(l).html(i),
        t.Type === mt && Bt.removeChild(l),
        l
    }
    ,
    yr.prototype.cloneOtHtmlEls = function(e) {
        var t = /otPcPanel|otPcCenter/;
        Vn.toggleEl = qt(e(".ot-tgl")).el.cloneNode(!0),
        Vn.arrowEl = qt(e("#onetrust-pc-sdk > " + Kt.P_Arrw_Cntr)).el.cloneNode(!0),
        Vn.subGrpEl = qt(e(Kt.P_Sub_Grp_Cntr)).el.cloneNode(!0),
        Vn.vListEl = qt(e(Kt.P_Ven_Lst_Cntr)).el.cloneNode(!0),
        Vn.cListEl = qt(e(Kt.P_Host_Lst_cntr)).el.cloneNode(!0),
        Vn.chkboxEl = qt(e(Kt.P_CBx_Cntr)).el.cloneNode(!0),
        Vn.accordionEl = qt(e(".ot-acc-cntr")).el.cloneNode(!0),
        t.test(Ot.pcName) && (Vn.plusMinusEl = qt(e(".ot-plus-minus")).el.cloneNode(!0)),
        Bt.removeChild(e(".ot-tgl")),
        Bt.removeChild(e("#onetrust-pc-sdk > " + Kt.P_Arrw_Cntr)),
        Bt.removeChild(e(Kt.P_Sub_Grp_Cntr)),
        Bt.removeChild(e(Kt.P_Ven_Lst_Cntr)),
        Bt.removeChild(e(Kt.P_Host_Lst_cntr)),
        Bt.removeChild(e(Kt.P_CBx_Cntr)),
        Bt.removeChild(e(".ot-acc-cntr")),
        t.test(Ot.pcName) && Bt.removeChild(e(".ot-plus-minus"))
    }
    ,
    yr.prototype.insertSelectAllEls = function(e) {
        var t = e(Kt.P_Select_Cntr + " .ot-sel-all-chkbox")
          , o = dr();
        o.id = Kt.P_Sel_All_Host_El,
        o.querySelector("input").id = "select-all-hosts-groups-handler",
        o.querySelector("label").setAttribute("for", "select-all-hosts-groups-handler"),
        qt(t).append(o);
        var n = dr();
        n.id = Kt.P_Sel_All_Vendor_Consent_El,
        n.querySelector("input").id = "select-all-vendor-groups-handler",
        n.querySelector("label").setAttribute("for", "select-all-vendor-groups-handler"),
        qt(t).append(n);
        var r = dr();
        r.id = Kt.P_Sel_All_Vendor_Leg_El,
        r.querySelector("input").id = "select-all-vendor-leg-handler",
        r.querySelector("label").setAttribute("for", "select-all-vendor-leg-handler"),
        qt(t).append(r)
    }
    ,
    yr.prototype.initializePreferenceCenterGroups = function(e, t) {
        var o = Ot.pcName;
        if (It.isV2Template) {
            gr.cloneOtHtmlEls(e);
            var n = Vn.chkboxEl.cloneNode(!0);
            n.querySelector("input").classList.add("category-filter-handler"),
            qt(e(Kt.P_Fltr_Modal + " " + Kt.P_Fltr_Option)).append(n),
            gr.insertSelectAllEls(e)
        }
        var r = qt(e("#onetrust-pc-sdk " + Kt.P_Category_Grp));
        o === ot || o === rt || o === nt ? Nt.PCenterEnableAccordion ? Bt.removeChild(r.el.querySelector(Kt.P_Category_Item + ":not(.ot-accordion-layout)")) : Bt.removeChild(r.el.querySelector(Kt.P_Category_Item + ".ot-accordion-layout")) : o === st && (Nt.PCenterEnableAccordion = !1);
        var i, s = e("#onetrust-pc-sdk " + Kt.P_Category_Item), a = It.isV2Template ? Vn.subGrpEl.cloneNode(!0) : qt(e(Kt.P_Sub_Grp_Cntr)), l = It.isV2Template ? "" : qt(e(Kt.P_Acc_Container + " " + Kt.P_Sub_Grp_Cntr));
        Nt.PCTemplateUpgrade && /otPcTab/.test(o) && (i = e(".ot-abt-tab").cloneNode(!0),
        Bt.removeChild(e(".ot-abt-tab"))),
        r.el.removeChild(s),
        It.isV2Template ? Nt.PCAccordionStyle === W.Caret && (qt(e("#onetrust-pc-sdk " + Kt.P_Vendor_List)).addClass("ot-enbl-chr"),
        Nt.PCenterEnableAccordion && qt(e("#onetrust-pc-sdk " + Kt.P_Content)).addClass("ot-enbl-chr")) : qt(s.querySelector(Kt.P_Sub_Grp_Cntr)).remove();
        var c = Nt.Groups.filter(function(e) {
            return e.Order
        })
          , d = 0 === r.el.children.length
          , u = e(Kt.P_Li_Hdr) || s.querySelector(Kt.P_Li_Hdr);
        Ot.legIntSettings.PAllowLI && Ot.grpContainLegalOptOut && "IAB2" === Nt.IabType && !Ot.legIntSettings.PShowLegIntBtn ? (u.querySelector("span:first-child").innerText = Nt.ConsentText,
        u.querySelector("span:last-child").innerText = Nt.LegitInterestText,
        It.isV2Template && (u.querySelector("span:first-child").innerText = Nt.PCenterConsentText,
        u.querySelector("span:last-child").innerText = Nt.PCenterLegIntColumnHeader),
        Nt.PCenterEnableAccordion && u ? u.classList.add("ot-leg-border-color") : "otPcList" === o && s.insertAdjacentElement("afterbegin", u)) : (Bt.removeChild(e("#onetrust-pc-sdk " + Kt.P_Li_Hdr)),
        Bt.removeChild(s.querySelector(Kt.P_Li_Hdr)));
        var p = e(".ot-tab-desc");
        Nt.PCTemplateUpgrade && (Ht.showVendorService ? ur.setHtmlTemplate(e("#onetrust-pc-sdk")) : ur.removeVSUITemplate(e("#onetrust-pc-sdk")));
        for (var h = 0; h < c.length; h++) {
            var g = c[h]
              , C = g.GroupName
              , y = g.CustomGroupId
              , f = s.cloneNode(!0)
              , v = "ot-group-id-" + y
              , k = "ot-header-id-" + y
              , m = "ot-desc-id-" + y;
            (f = qt(f).el).setAttribute("data-optanongroupid", y);
            var b = f.querySelector("input,button");
            b && (b.setAttribute("aria-controls", m),
            b.setAttribute("aria-labelledby", k)),
            gr.setParentGroupName(f, C, k, m),
            o === it && (g.ShowVendorList && "IAB2" === Nt.IabType ? (Bt.removeChild(f.querySelector("p:not(.ot-always-active)")),
            Bt.removeChild(f.querySelector(Kt.P_Acc_Txt + ":not(" + Kt.P_Acc_Container + ")")),
            g.SubGroups.length || It.isV2Template || Bt.removeChild(f.querySelector(Kt.P_Sub_Grp_Cntr))) : Bt.removeChild(f.querySelector(Kt.P_Acc_Container)));
            var P = gr.setParentGroupDescription(f, g, Nt, m, v);
            It.isV2Template ? gr.setToggle(f, P, g, v, k) : gr.setToggleProps(f, P, g, v, k);
            var S = !!e("#onetrust-pc-sdk " + Kt.P_Category_Grp).querySelector(Kt.P_Category_Item)
              , A = r.el.querySelectorAll(Kt.P_Category_Item + ":not(.ot-vnd-item)");
            if (A = A[A.length - 1],
            d ? r.append(f) : S ? Ft.insertAfter(f, A) : Ft.insertAfter(f, r.el.querySelector(Kt.P_Li_Hdr) || r.el.querySelector("h3")),
            0 < g.SubGroups.length && g.ShowSubgroup) {
                var T = o === it && g.ShowVendorList && "IAB2" === Nt.IabType && !Nt.PCTemplateUpgrade;
                gr.setSubGrps(g, T ? l : a, f, Nt)
            }
            var I = Nt.PCGrpDescLinkPosition === E.Top;
            g.Type === mt && I && (P = f.querySelector(Kt.P_Sub_Grp_Cntr));
            var L = I ? P : null;
            if (gr.setVendorListBtn(f, e, t, g, L, Nt),
            gr.setHostListBtn(f, e, t, g),
            Ht.showVendorService && Nt.VendorServiceConfig.PCVSCategoryView) {
                var _ = Kt.P_Acc_Txt;
                o === st && (_ = Kt.P_Desc_Container);
                var V = f.querySelector(_);
                ur.insertVendorServiceHtml(g, V)
            }
            Ht.dataGroupState.push(g)
        }
        if ("otPcTab" === o)
            if (i && e("#onetrust-pc-sdk " + Kt.P_Category_Grp).insertAdjacentElement("afterbegin", i),
            p && 640 < window.innerWidth && qt(p).append(t.querySelectorAll("#onetrust-pc-sdk " + Kt.P_Desc_Container)),
            Nt.IsIabEnabled)
                e(Kt.P_Desc_Container + " .category-vendors-list-handler").innerHTML = Nt.VendorListText + "&#x200E;";
            else {
                var B = e(Kt.P_Desc_Container + " .category-vendors-list-handler");
                B && B.parentElement.removeChild(B)
            }
    }
    ,
    yr.prototype.jsonAddAboutCookies = function(e) {
        var t = {};
        return t.GroupName = e.AboutCookiesText,
        t.GroupDescription = e.MainInfoText,
        t.ShowInPopup = !0,
        t.Order = 0,
        t.IsAboutGroup = !0,
        t
    }
    ,
    yr.prototype.setVendorListBtn = function(e, t, o, n, r, i) {
        var s = Ot.pcName;
        if (n.ShowVendorList) {
            var a = void 0
              , l = void 0;
            if (It.isV2Template ? a = (l = Vn.vListEl.cloneNode(!0)).querySelector(".category-vendors-list-handler") : l = (a = e.querySelector(".category-vendors-list-handler")).parentElement,
            a.innerHTML = i.VendorListText + "&#x200E;",
            a.setAttribute("aria-label", Nt.PCOpensVendorDetailsAlert),
            a.setAttribute("data-parent-id", n.CustomGroupId),
            i.PCGrpDescType === G.UserFriendly && a.insertAdjacentHTML("afterend", "<a href='" + Nt.IabLegalTextUrl + "?lang=" + Ht.consentLanguage + "' rel=\"noopener\" target='_blank'>&nbsp;|&nbsp;" + i.PCVendorFullLegalText + '&nbsp;<span class="ot-scrn-rdr">' + Nt.NewWinTxt + "</span></a>"),
            It.isV2Template) {
                var c = e;
                s === st ? c = e.querySelector("" + Kt.P_Desc_Container) : i.PCenterEnableAccordion && (c = e.querySelector(Kt.P_Acc_Txt)),
                c.insertAdjacentElement("beforeend", l)
            }
            r && r.insertAdjacentElement("beforebegin", l)
        } else if (!It.isV2Template) {
            if (s !== rt && s !== ot || i.PCenterEnableAccordion) {
                if (s === it || s === rt || s === ot && i.PCenterEnableAccordion) {
                    var d = t("#vendor-list-container")
                      , u = e.querySelector(Kt.P_Acc_Txt);
                    d && o.querySelector("" + Kt.P_Content).removeChild(d),
                    It.isV2Template || qt(u).el.removeChild(u.querySelector(Kt.P_Ven_Lst_Cntr))
                }
            } else
                Bt.removeChild(e.querySelector(Kt.P_Ven_Lst_Cntr));
            if (s === st || s === nt) {
                var p = e.querySelector(Kt.P_Ven_Lst_Cntr);
                p && p.parentElement.removeChild(p)
            }
        }
    }
    ,
    yr.prototype.setHostListBtn = function(e, t, o, n) {
        var r = Ot.pcName
          , i = !1;
        Nt.showCookieList && (i = -1 < Bt.findIndex(y(n.SubGroups, [n]), function(e) {
            return -1 === bt.indexOf(e.Type) && e.FirstPartyCookies.length
        }));
        var s = Ht.showGeneralVendors && n.GeneralVendorsIds && n.GeneralVendorsIds.length;
        if (!Ht.showVendorService && (Nt.showCookieList || Ht.showGeneralVendors) && (n.ShowHostList || i || s)) {
            var a = void 0;
            if (It.isV2Template) {
                var l = Vn.cListEl.cloneNode(!0);
                a = l.querySelector(".category-host-list-handler");
                var c = e;
                r === st ? c = e.querySelector("" + Kt.P_Desc_Container) : Nt.PCenterEnableAccordion && (c = e.querySelector(Kt.P_Acc_Txt)),
                c.insertAdjacentElement("beforeend", l)
            } else
                a = e.querySelector(".category-host-list-handler");
            if (a) {
                var d = Ht.showGeneralVendors ? Nt.GroupGenVenListLabel : Nt.ThirdPartyCookieListText
                  , u = Ht.showGeneralVendors ? Nt.PCenterVendorListScreenReader : Nt.PCOpensCookiesDetailsAlert;
                a.innerHTML = d + "&#x200E;",
                a.setAttribute("aria-label", u),
                a.setAttribute("data-parent-id", n.CustomGroupId)
            }
        } else if (r === it) {
            var p = t("#vendor-list-container")
              , h = e.querySelector(Kt.P_Acc_Txt);
            p && o.querySelector("" + Kt.P_Content).removeChild(p),
            h.querySelector(Kt.P_Host_Lst_cntr) && qt(h).el.removeChild(h.querySelector(Kt.P_Host_Lst_cntr))
        } else {
            var g = e.querySelector(Kt.P_Host_Lst_cntr);
            g && g.parentElement.removeChild(g)
        }
    }
    ,
    yr.prototype.setSubGrps = function(T, I, L, _) {
        var V = this
          , B = Ot.pcName
          , E = _.PCGrpDescType === G.Legal
          , w = y(St, Pt)
          , x = B === it && T.ShowVendorList && "IAB2" === _.IabType;
        if (x && !Nt.PCTemplateUpgrade) {
            var e = L.querySelector(Kt.P_Sub_Grp_Cntr);
            e.parentElement.removeChild(e)
        }
        T.SubGroups.forEach(function(e) {
            var t;
            "IAB2" !== Ot.iabType || e.Type !== ft || e.HasConsentOptOut || (t = !0);
            var o, n, r = It.isV2Template ? I.cloneNode(!0) : I.el.cloneNode(!0), i = r.querySelector(Kt.P_Subgp_ul), s = r.querySelector(Kt.P_Subgrp_li).cloneNode(!0), a = e.CustomGroupId, l = "ot-sub-group-id-" + a, c = Xt.getGrpStatus(e).toLowerCase(), d = Xt.getGrpStatus(T).toLowerCase(), u = s.querySelector(".cookie-subgroup>h4, .cookie-subgroup>h5, .cookie-subgroup>h6, .ot-subgrp>h4, .ot-subgrp>h5, .ot-subgrp>h6"), p = s.querySelector(Kt.P_Tgl_Cntr);
            s.setAttribute("data-optanongroupid", a),
            It.isV2Template ? ((n = Vn.toggleEl.cloneNode(!0)).querySelector("input").setAttribute("data-optanongroupid", a),
            n.querySelector("input").classList.add("cookie-subgroup-handler"),
            o = n.cloneNode(!0),
            p.insertAdjacentElement("beforeend", o)) : (o = s.querySelector(".ot-toggle")).querySelector("input").setAttribute("data-optanongroupid", a),
            qt(r.querySelector(Kt.P_Subgp_ul)).html(""),
            qt(u).html(e.GroupName),
            o.querySelector("input").setAttribute("id", l),
            o.querySelector("input").setAttribute("aria-label", e.GroupName),
            o.querySelector("label").setAttribute("for", l);
            var h = qt(s.querySelector(Kt.P_Subgrp_Desc));
            if (x) {
                var g = e.DescriptionLegal && E ? e.DescriptionLegal : e.GroupDescription;
                h.html(g)
            } else {
                g = Sn.safeFormattedGroupDescription(e);
                var C = !1;
                -1 < Tt.indexOf(e.Type) && E && (C = !0,
                g = e.DescriptionLegal),
                _.PCenterEnableAccordion && C || (h = qt(s.querySelector("p"))),
                T.ShowSubGroupDescription ? h.html(g) : h.html("")
            }
            if (T.ShowSubgroupToggle && -1 < w.indexOf(e.Type)) {
                var y = Sn.isGroupActive(e);
                y && (s.querySelector("input").setAttribute("checked", ""),
                "always active" === d && -1 === Tt.indexOf(e.Type) && (s.querySelector("input").disabled = !0,
                s.querySelector("input").setAttribute("disabled", !0)));
                var f = p.querySelector(".ot-label-status");
                if (Nt.PCShowConsentLabels ? f.innerHTML = y ? Nt.PCActiveText : Nt.PCInactiveText : Bt.removeChild(f),
                Ot.legIntSettings.PAllowLI && e.Type === ft && e.HasLegIntOptOut)
                    if (Ot.legIntSettings.PShowLegIntBtn)
                        gr.setLegIntButton(s, e);
                    else {
                        var v = p.cloneNode(!0);
                        p.insertAdjacentElement("afterend", v);
                        var k = v.querySelector(".ot-label-status")
                          , m = v.querySelector("input");
                        m.setAttribute("id", l + "-leg-out"),
                        v.querySelector("label").setAttribute("for", l + "-leg-out"),
                        e.IsLegIntToggle = !0;
                        var b = Sn.isGroupActive(e);
                        Nt.PCShowConsentLabels ? k.innerHTML = b ? Nt.PCActiveText : Nt.PCInactiveText : Bt.removeChild(k),
                        Bt.setCheckedAttribute(null, m, b),
                        e.IsLegIntToggle = !1
                    }
            } else
                "always active" === c && (T.ShowSubgroupToggle || -1 === At.indexOf(e.Type)) || (t = !0);
            if (t && (o.classList.add("ot-hide-tgl"),
            o.querySelector("input").setAttribute(V._ariaHidden, !0)),
            "always active" !== c || t || (o && o.parentElement.removeChild(o),
            s.querySelector(Kt.P_Tgl_Cntr).classList.add("ot-always-active-subgroup"),
            gr.setAlwaysActive(s, !0)),
            "COOKIE" === e.Type && -1 !== e.Parent.indexOf("STACK") && Lt(r, "display: none;"),
            qt(i).append(s),
            It.isV2Template) {
                var P = L;
                "otPcTab" === B ? P = L.querySelector("" + Kt.P_Desc_Container) : _.PCenterEnableAccordion && (P = L.querySelector(Kt.P_Acc_Txt)),
                P.insertAdjacentElement("beforeend", r)
            } else {
                var S = L.querySelector(Kt.P_Category_Item + " " + Kt.P_Ven_Lst_Cntr);
                S && S.insertAdjacentElement("beforebegin", r)
            }
            if (Ht.showVendorService && Nt.VendorServiceConfig.PCVSCategoryView) {
                var A = i;
                ur.insertVendorServiceHtml(T, A)
            }
        })
    }
    ,
    yr.prototype.getInputEle = function(e) {
        return Ht.showVendorService ? (Nt.PCCategoryStyle === se.Checkbox && e.classList.add("ot-checkbox-consent"),
        dr()) : Vn.toggleEl.cloneNode(!0)
    }
    ,
    yr.prototype.setToggle = function(e, t, o, n, r) {
        var i = gr.getInputEle(e);
        i.querySelector("input").classList.add("category-switch-handler");
        var s = i.querySelector("input")
          , a = e.querySelector(Kt.P_Category_Header)
          , l = Sn.isGroupActive(o)
          , c = "always active" === Xt.getGrpStatus(o).toLowerCase()
          , d = o.OptanonGroupId.toString()
          , u = !0;
        if ("IAB2" !== Ot.iabType || o.Type !== ft && o.Type !== mt || o.HasConsentOptOut || (u = !1),
        qt(i.querySelector("label")).attr("for", n),
        qt(i.querySelector(".ot-label-txt")).html(o.GroupName),
        Ot.legIntSettings.PAllowLI && o.Type === ft && o.HasLegIntOptOut)
            if (Ot.legIntSettings.PShowLegIntBtn)
                gr.setLegIntButton(e, o, !0, t);
            else {
                var p = i.cloneNode(!0);
                o.IsLegIntToggle = !0;
                var h = Sn.isGroupActive(o)
                  , g = p.querySelector(".ot-label-status");
                Nt.PCShowConsentLabels ? g.innerHTML = h ? Nt.PCActiveText : Nt.PCInactiveText : Bt.removeChild(g),
                o.IsLegIntToggle = !1,
                Sn.setInputID(p.querySelector("input"), n + "-leg-out", d, h, r),
                qt(p.querySelector("label")).attr("for", n + "-leg-out"),
                a.insertAdjacentElement("afterend", p)
            }
        var C = i.querySelector(".ot-label-status");
        Nt.PCShowConsentLabels ? C.innerHTML = l ? Nt.PCActiveText : Nt.PCInactiveText : Bt.removeChild(C);
        var y = Nt.PCCategoryStyle === se.Toggle;
        !c && u || !y || (i.classList.add("ot-hide-tgl"),
        i.querySelector("input").setAttribute(this._ariaHidden, "true")),
        u && (Ht.showVendorService ? (c && (gr.setAlwaysActive(e),
        i.querySelector("input").setAttribute("disabled", "true")),
        c && y || gr.insertAccordionInputHeader(a, i),
        Sn.setInputID(s, n, d, l, r),
        gr.insertAccordionPointer(e, a)) : (gr.insertAccordionPointer(e, a),
        c ? gr.setAlwaysActive(e) : (gr.insertAccordionInputHeader(a, i),
        Sn.setInputID(s, n, d, l, r))))
    }
    ,
    yr.prototype.insertAccordionInputHeader = function(e, t) {
        if (Ht.showVendorService) {
            var o = "beforebegin";
            Nt.PCCategoryStyle === se.Toggle && (o = "afterend"),
            e.insertAdjacentElement(o, t)
        } else
            e.insertAdjacentElement("afterend", t)
    }
    ,
    yr.prototype.insertAccordionPointer = function(e, t) {
        if (e.classList.add("ot-vs-config"),
        Nt.PCenterEnableAccordion)
            if (Ht.showVendorService) {
                var o = e.querySelector(Kt.P_Acc_Header)
                  , n = void 0
                  , r = void 0;
                n = Nt.PCAccordionStyle === W.Caret ? (r = "beforeend",
                Vn.arrowEl.cloneNode(!0)) : (r = Nt.PCCategoryStyle === se.Checkbox ? "beforeend" : "afterbegin",
                Vn.plusMinusEl.cloneNode(!0)),
                o.insertAdjacentElement(r, n)
            } else
                Nt.PCAccordionStyle === W.Caret ? t.insertAdjacentElement("afterend", Vn.arrowEl.cloneNode(!0)) : t.insertAdjacentElement("beforebegin", Vn.plusMinusEl.cloneNode(!0))
    }
    ,
    yr.prototype.setToggleProps = function(e, t, o, n, r) {
        var i = e.querySelectorAll("input:not(.cookie-subgroup-handler)")
          , s = e.querySelectorAll("label")
          , a = Sn.isGroupActive(o)
          , l = o.CustomGroupId
          , c = e.querySelector(".label-text");
        c && qt(c).html(o.GroupName);
        for (var d = 0; d < i.length; d++)
            if (s[d] && qt(s[d]).attr("for", n),
            2 <= i.length && 0 === d)
                qt(i[d]).attr("id", n + "-toggle");
            else {
                var u = !0;
                if ("IAB2" !== Ot.iabType || o.Type !== ft && o.Type !== mt || o.HasConsentOptOut || (u = !1),
                Ot.legIntSettings.PAllowLI && o.Type === ft && o.HasLegIntOptOut)
                    if (Ot.legIntSettings.PShowLegIntBtn)
                        gr.setLegIntButton(e, o, !0, t);
                    else {
                        var p = e.querySelector(Kt.P_Tgl_Cntr + ":not(" + Kt.P_Subgrp_Tgl_Cntr + ")") || e.querySelector(".ot-toggle")
                          , h = p.cloneNode(!0);
                        p.insertAdjacentElement("afterend", h);
                        var g = h.querySelector("input");
                        o.IsLegIntToggle = !0;
                        var C = Sn.isGroupActive(o);
                        o.IsLegIntToggle = !1,
                        Sn.setInputID(g, n + "-leg-out", l, C, r),
                        qt(h.querySelector("label")).attr("for", n + "-leg-out"),
                        Bt.removeChild(h.querySelector(Kt.P_Arrw_Cntr))
                    }
                var y = "always active" === Xt.getGrpStatus(o).toLowerCase();
                if (y || !u) {
                    var f = i[d].closest(".ot-toggle");
                    f && (f.classList.add("ot-hide-tgl"),
                    f.querySelector("input").setAttribute(this._ariaHidden, !0))
                }
                u && (y && gr.setAlwaysActive(e),
                Sn.setInputID(i[d], n, l, a, r))
            }
    }
    ,
    yr.prototype.setAlwaysActive = function(e, t) {
        void 0 === t && (t = !1);
        var o = Ot.pcName;
        if (o === it || o === st || t)
            e.querySelector(Kt.P_Tgl_Cntr).insertAdjacentElement("afterbegin", qt("<div class='ot-always-active'>" + Nt.AlwaysActiveText + "</div>", "ce").el);
        else {
            var n = e.querySelector(Kt.P_Category_Header);
            !It.isV2Template && Nt.PCenterEnableAccordion && (n = e.querySelector(Kt.P_Arrw_Cntr)),
            qt(n).el.insertAdjacentElement("afterend", qt("<div class='ot-always-active'>" + Nt.AlwaysActiveText + "</div>", "ce").el)
        }
        if (Nt.PCenterEnableAccordion) {
            var r = e.querySelector(Kt.P_Acc_Header);
            r && r.classList.add("ot-always-active-group")
        } else {
            var i = e.querySelector("" + Kt.P_Desc_Container);
            i && i.classList.add("ot-always-active-group"),
            e.classList.add("ot-always-active-group")
        }
    }
    ,
    yr);
    function yr() {
        this._ariaHidden = "aria-hidden"
    }
    var fr, vr = (kr.prototype.showBanner = function() {
        var e = Ot.bannerName
          , t = qt(this.El);
        Ht.skipAddingHTML && "none" === getComputedStyle(t.el[0]).getPropertyValue("display") && e !== Xe && e !== Ye && e !== Ze ? t.css("display: block;") : Nt.BAnimation === le.SlideIn ? this.slideInAnimation(t, e) : Nt.BAnimation === le.FadeIn && t.addClass("ot-fade-in")
    }
    ,
    kr.prototype.insertAlertHtml = function() {
        function e(e) {
            return r.querySelector(e)
        }
        function t(e) {
            return r.querySelectorAll(e)
        }
        var o = this
          , n = Nt.BannerPurposeTitle || Nt.BannerPurposeDescription || Nt.BannerFeatureTitle || Nt.BannerFeatureDescription || Nt.BannerInformationTitle || Nt.BannerInformationDescription
          , r = document.createDocumentFragment()
          , i = Ot.bannerName
          , s = document.createElement("div");
        qt(s).html(hn.bannerGroup.html);
        var a = s.querySelector("#onetrust-banner-sdk");
        if (It.fp.CookieV2SSR)
            qt(r).append(a),
            this._rejectBtn = e("#onetrust-reject-all-handler"),
            this._acceptBtn = e("#onetrust-accept-btn-handler");
        else {
            var l = [{
                type: "purpose",
                titleKey: "BannerPurposeTitle",
                descriptionKey: "BannerPurposeDescription",
                identifier: "purpose-option"
            }, {
                type: "feature",
                titleKey: "BannerFeatureTitle",
                descriptionKey: "BannerFeatureDescription",
                identifier: "feature-option"
            }, {
                type: "information",
                titleKey: "BannerInformationTitle",
                descriptionKey: "BannerInformationDescription",
                identifier: "information-option"
            }];
            if (hn.bannerGroup) {
                Nt.BannerRelativeFontSizesToggle && qt(a).addClass("otRelFont"),
                (Nt.BInitialFocus || Nt.BInitialFocusLinkAndButton) && a.setAttribute("tabindex", "0"),
                Nt.useRTL && qt(a).attr("dir", "rtl"),
                "IAB2" === Ot.iabType && Nt.BannerDPDDescription.length && qt(a).addClass("ot-iab-2");
                var c = Nt.BannerPosition;
                if (c && ("bottom-left" === c ? qt(a).addClass("ot-bottom-left") : "bottom-right" === c ? qt(a).addClass("ot-bottom-right") : qt(a).addClass(c)),
                qt(r).append(a),
                Nt.BannerTitle ? (qt(e("#onetrust-policy-title")).html(Nt.BannerTitle),
                qt(e('[role="alertdialog"]')).attr("aria-label", Nt.BannerTitle)) : (Bt.removeChild(e("#onetrust-policy-title")),
                qt(e("#onetrust-banner-sdk")).addClass("ot-wo-title"),
                qt(e('[role="alertdialog"]')).attr("aria-label", Nt.AriaPrivacy)),
                !Nt.IsIabEnabled && Ht.showGeneralVendors && Nt.BannerNonIABVendorListText) {
                    var d = document.createElement("div");
                    d.setAttribute("id", "ot-gv-link-ctnr"),
                    qt(d).html('<button class="ot-link-btn ot-gv-list-handler">' + Nt.BannerNonIABVendorListText + "</button>"),
                    qt(e("#onetrust-policy")).el.appendChild(d)
                }
                qt(e("#onetrust-policy-text")).html(Nt.AlertNoticeText),
                Nt.BShowPolicyLink && Nt.BShowImprintLink && qt(e("#onetrust-policy-text a")).length ? (qt(e("#onetrust-policy-text a:first-child")).attr("aria-label", Nt.BCookiePolicyLinkScreenReader),
                qt(e("#onetrust-policy-text a:last-child")).attr("aria-label", Nt.BImprintLinkScreenReader)) : Nt.BShowPolicyLink && qt(e("#onetrust-policy-text a")).length ? qt(e("#onetrust-policy-text a")).attr("aria-label", Nt.BCookiePolicyLinkScreenReader) : Nt.BShowImprintLink && qt(e("#onetrust-policy-text a")).length && qt(e("#onetrust-policy-text a")).attr("aria-label", Nt.BImprintLinkScreenReader),
                "IAB2" === Nt.IabType && Nt.BannerDPDDescription.length && i !== et ? (qt(e(".ot-dpd-container .ot-dpd-title")).html(Nt.BannerDPDTitle),
                qt(e(".ot-dpd-container .ot-dpd-desc")).html(Nt.BannerDPDDescription.join(",&nbsp;"))) : Bt.removeChild(e(".ot-dpd-container"));
                var u = qt(e("#onetrust-group-container"));
                "IAB2" === Ot.iabType && Nt.BannerAdditionalDescription.trim() && this.setAdditionalDesc(e);
                var p = "IAB2" === Nt.IabType && Nt.BannerDPDDescription.length ? i !== et ? qt(e(".ot-dpd-container .ot-dpd-desc")) : u : qt(e("#onetrust-policy-text"));
                Nt.IsIabEnabled && Nt.BannerIABPartnersLink && p.append('<button class="ot-link-btn onetrust-vendors-list-handler">\n                ' + Nt.BannerIABPartnersLink + "\n                </button>"),
                Nt.showBannerAcceptButton ? (this._acceptBtn = e("#onetrust-accept-btn-handler"),
                qt(this._acceptBtn).html(Nt.AlertAllowCookiesText),
                i !== Ze || Nt.showBannerCookieSettings || Nt.BannerShowRejectAllButton || qt(this._acceptBtn.parentElement).addClass("accept-btn-only")) : Bt.removeChild(e("#onetrust-accept-btn-handler")),
                Nt.BannerShowRejectAllButton && Nt.BannerRejectAllButtonText.trim() ? (this._rejectBtn = e("#onetrust-reject-all-handler"),
                qt(this._rejectBtn).html(Nt.BannerRejectAllButtonText),
                e("#onetrust-button-group-parent").classList.add("has-reject-all-button")) : (Bt.removeChild(e("#onetrust-reject-all-handler")),
                Bt.removeChild(e("#onetrust-reject-btn-container")));
                var h = qt(e("#onetrust-pc-btn-handler"));
                Nt.showBannerCookieSettings ? (h.html(Nt.AlertMoreInfoText),
                Nt.BannerSettingsButtonDisplayLink && h.addClass("cookie-setting-link"),
                i !== Ze || Nt.showBannerAcceptButton || h.addClass("cookie-settings-btn-only")) : Bt.removeChild(h.el);
                var g = !Nt.showBannerAcceptButton && !Nt.showBannerCookieSettings && !Nt.BannerShowRejectAllButton;
                g && e("#onetrust-button-group-parent").parentElement.removeChild(e("#onetrust-button-group-parent"));
                var C = Nt.showBannerCloseButton
                  , y = qt(t(".banner-close-button")).el
                  , f = e("#onetrust-button-group")
                  , v = Nt.BCloseButtonType === de.Link;
                if (C)
                    for (k = 0; k < y.length; k++)
                        v ? (qt(y[k]).html(Nt.BContinueText),
                        qt(a).addClass("ot-close-btn-link"),
                        qt(y[k]).addClass("ot-close-link"),
                        qt(y[k]).removeClass("onetrust-close-btn-ui"),
                        qt(y[k]).removeClass("ot-close-icon"),
                        i !== Qe && i !== $e || (f.insertAdjacentElement("afterbegin", e(".onetrust-close-btn-handler").parentElement),
                        qt(y[k]).attr("tabindex", "1"))) : qt(y[k]).el.setAttribute("aria-label", Nt.BannerCloseButtonText || "Close Cookie Banner");
                else {
                    for (var k = 0; k < y.length; k++)
                        qt(y[k].parentElement).el.removeChild(y[k]);
                    i !== Ye && i !== $e || Bt.removeChild(e("#onetrust-close-btn-container-mobile"))
                }
                if (i === Ye && ("IAB2" === Ot.iabType && (u.removeClass("ot-sdk-eight"),
                Nt.showBannerAcceptButton && f.insertAdjacentElement("afterbegin", this._acceptBtn),
                Nt.showBannerCookieSettings && f.insertAdjacentElement("beforeend", e("#onetrust-pc-btn-handler"))),
                C && !g && "IAB2" === Ot.iabType ? u.addClass("ot-sdk-nine") : C && g ? u.addClass("ot-sdk-eleven") : !C && g ? u.addClass("ot-sdk-twelve") : C || g || "IAB2" !== Ot.iabType || (u.addClass("ot-sdk-ten"),
                qt(e("#onetrust-button-group-parent")).addClass("ot-sdk-two"),
                qt(e("#onetrust-button-group-parent")).removeClass("ot-sdk-three"))),
                C && i === Qe && "IAB2" === Ot.iabType && !v) {
                    var m = e(".banner-close-btn-container");
                    m.parentElement.removeChild(m),
                    qt(a).el.insertAdjacentElement("beforeEnd", m),
                    qt(e("#onetrust-banner-sdk .ot-sdk-container")).addClass("ot-top-cntr")
                }
                var b = qt(e("#banner-options")).el;
                n ? (i === $e ? this.setFloatingRoundedIconBannerCmpOptions(e, l) : (this.setCmpBannerOptions(e, l),
                i === et && u.el.insertAdjacentElement("beforeend", b)),
                qt(window).on("resize", function() {
                    window.innerWidth <= 896 && o.setBannerOptionContent()
                })) : (Ot.bannerName === Qe && (b = qt(e(".banner-options-card")).el),
                Bt.removeChild(b))
            }
        }
        Ot.bannerName === et && It.moduleInitializer.IsSuppressPC && (Ht.dataGroupState = Nt.Groups.filter(function(e) {
            return e.Order
        })),
        Ot.bannerName === et && (this._fourBtns = Nt.BannerShowRejectAllButton && Nt.showBannerAcceptButton && Nt.showBannerCookieSettings && Nt.BShowSaveBtn,
        this._saveBtn = e(".ot-bnr-save-handler"),
        this._settingsBtn = e("#onetrust-pc-btn-handler"),
        this._btnsCntr = e(".banner-actions-container"),
        Nt.BShowSaveBtn ? qt(this._saveBtn).html(Nt.BSaveBtnTxt) : (Bt.removeChild(this._saveBtn),
        this._saveBtn = null),
        Mt.insertFooterLogo(t(".ot-bnr-footer-logo a")),
        this._descriptCntr = e(".ot-cat-lst"),
        this.setBannerBtn(),
        window.addEventListener("resize", function() {
            o.setBannerBtn()
        }),
        this._fourBtns && qt(e("#onetrust-banner-sdk")).addClass("has-reject-all-button"),
        this.insertGrps(e));
        var P = document.createElement("div");
        qt(P).append(r),
        Ot.ignoreInjectingHtmlCss || (qt("#onetrust-consent-sdk").append(P.firstChild),
        n && this.setBannerOptionContent()),
        this.setBnrBtnGrpAlignment()
    }
    ,
    kr.prototype.setBnrBtnGrpAlignment = function() {
        var e = qt("#onetrust-group-container").el
          , t = qt("#onetrust-button-group-parent").el;
        (e.length && e[0].clientHeight) < (t.length && t[0].clientHeight) ? qt("#onetrust-banner-sdk").removeClass("vertical-align-content") : qt("#onetrust-banner-sdk").addClass("vertical-align-content");
        var o = document.querySelector("#onetrust-button-group-parent button:first-of-type")
          , n = document.querySelector("#onetrust-button-group-parent button:last-of-type");
        n && o && 1 < Math.abs(n.offsetTop - o.offsetTop) && qt("#onetrust-banner-sdk").addClass("ot-buttons-fw")
    }
    ,
    kr.prototype.slideInAnimation = function(e, t) {
        t === Ye ? "bottom" === Nt.BannerPosition ? (e.css("bottom: -99px;"),
        e.animate({
            bottom: "0px"
        }, 1e3),
        Ht.bnrAnimationInProg = !0,
        setTimeout(function() {
            e.css("bottom: 0px;"),
            Ht.bnrAnimationInProg = !1
        }, 1e3)) : (e.css("top: -99px; bottom: auto;"),
        Ot.pagePushedDown && !Ao.checkIsBrowserIE11OrBelow() ? Ao.BannerPushDownHandler() : (e.animate({
            top: "0"
        }, 1e3),
        Ht.bnrAnimationInProg = !0,
        setTimeout(function() {
            e.css("top: 0px; bottom: auto;"),
            Ht.bnrAnimationInProg = !1
        }, 1e3))) : t !== Xe && t !== Ze || (e.css("bottom: -300px;"),
        e.animate({
            bottom: "1em"
        }, 2e3),
        Ht.bnrAnimationInProg = !0,
        setTimeout(function() {
            e.css("bottom: 1rem;"),
            Ht.bnrAnimationInProg = !1
        }, 2e3))
    }
    ,
    kr.prototype.setBannerBtn = function() {
        window.innerWidth <= 600 ? (Bt.insertElement(this._btnsCntr, this._settingsBtn, "afterbegin"),
        Bt.insertElement(this._btnsCntr, this._saveBtn, "afterbegin"),
        Bt.insertElement(this._btnsCntr, this._acceptBtn, "afterbegin"),
        Bt.insertElement(this._btnsCntr, this._rejectBtn, "afterbegin")) : this._fourBtns ? (this._descriptCntr.insertAdjacentElement("beforeend", this._settingsBtn),
        this._acceptBtn.insertAdjacentElement("beforebegin", this._rejectBtn),
        this._btnsCntr.insertAdjacentElement("beforebegin", this._saveBtn)) : (Bt.insertElement(this._btnsCntr, this._settingsBtn, "beforebegin"),
        Bt.insertElement(this._btnsCntr, this._saveBtn, this._settingsBtn ? "afterbegin" : "beforebegin"),
        Bt.insertElement(this._btnsCntr, this._rejectBtn, "beforeend"),
        Bt.insertElement(this._btnsCntr, this._acceptBtn, "beforeend"))
    }
    ,
    kr.prototype.setCmpBannerOptions = function(i, e) {
        var s = qt(i("#banner-options .banner-option")).el.cloneNode(!0);
        qt(i("#banner-options")).html("");
        var a = 1;
        e.forEach(function(e) {
            var t = s.cloneNode(!0)
              , o = Nt[e.titleKey]
              , n = Nt[e.descriptionKey];
            if (o || n) {
                t.querySelector(".banner-option-header :first-child").innerHTML = o;
                var r = t.querySelector(".banner-option-details");
                n ? (r.setAttribute("id", "option-details-" + a++),
                r.innerHTML = n) : r.parentElement.removeChild(r),
                qt(i("#banner-options")).el.appendChild(t)
            }
        })
    }
    ,
    kr.prototype.setFloatingRoundedIconBannerCmpOptions = function(r, e) {
        var i = qt(r("#banner-options button")).el.cloneNode(!0)
          , n = qt(r(".banner-option-details")).el.cloneNode(!0);
        qt(r("#banner-options")).html(""),
        e.forEach(function(e) {
            var t = i.cloneNode(!0)
              , o = Nt[e.titleKey]
              , n = Nt[e.descriptionKey];
            (o || n) && (t.setAttribute("id", e.identifier),
            t.querySelector(".banner-option-header :first-child").innerHTML = o,
            qt(r("#banner-options")).el.appendChild(t))
        }),
        e.forEach(function(e) {
            var t = Nt[e.descriptionKey];
            if (t) {
                var o = n.cloneNode(!0);
                o.innerHTML = t,
                o.classList.add(e.identifier),
                qt(r("#banner-options")).el.appendChild(o)
            }
        })
    }
    ,
    kr.prototype.setBannerOptionContent = function() {
        Ot.bannerName !== Ye && Ot.bannerName !== $e || setTimeout(function() {
            if (window.innerWidth < 769) {
                var e = qt("#banner-options").el[0];
                qt("#onetrust-group-container").el[0].appendChild(e)
            } else
                e = qt("#banner-options").el[0],
                Ot.bannerName === $e ? qt(".banner-content").el[0].appendChild(e) : qt("#onetrust-banner-sdk .ot-sdk-container").el[0].appendChild(e)
        })
    }
    ,
    kr.prototype.setAdditionalDesc = function(e) {
        var t = Nt.BannerAdditionalDescPlacement
          , o = document.createElement("span");
        o.classList.add("ot-b-addl-desc"),
        o.innerHTML = Nt.BannerAdditionalDescription;
        var n = e("#onetrust-policy-text");
        if (t === x.AfterTitle)
            n.insertAdjacentElement("beforeBegin", o);
        else if (t === x.AfterDescription)
            n.insertAdjacentElement("afterEnd", o);
        else if (t === x.AfterDPD) {
            var r = e(".ot-dpd-container .ot-dpd-desc");
            Nt.ChoicesBanner && (r = e("#onetrust-group-container")),
            r.insertAdjacentElement("beforeEnd", o)
        }
    }
    ,
    kr.prototype.insertGrps = function(e) {
        var p = e(".ot-cat-item").cloneNode(!0);
        Bt.removeChild(e(".ot-cat-item")),
        Nt.BCategoryStyle === se.Checkbox ? Bt.removeChild(p.querySelector(".ot-tgl")) : (Bt.removeChild(p.querySelector(".ot-chkbox")),
        qt(p).addClass("ot-cat-bdr"));
        var h = e(".ot-cat-lst ul");
        Nt.Groups.forEach(function(e) {
            var t = p.cloneNode(!0)
              , o = t.querySelector(".ot-tgl,.ot-chkbox")
              , n = e.GroupName
              , r = e.CustomGroupId
              , i = "ot-bnr-grp-id-" + r
              , s = "ot-bnr-hdr-id-" + r
              , a = -1 !== At.indexOf(e.Type)
              , l = Xt.getGrpStatus(e).toLowerCase() === De || a
              , c = Sn.isGroupActive(e) || a;
            qt(o.querySelector("label")).attr("for", i),
            qt(o.querySelector(".ot-label-txt")).html(e.GroupName);
            var d = o.querySelector("input");
            l && (Nt.BCategoryStyle === se.Toggle ? (Bt.removeChild(o),
            t.insertAdjacentElement("beforeend", qt("<div class='ot-always-active'>" + Nt.AlwaysActiveText + "</div>", "ce").el)) : qt(d).attr("disabled", !0)),
            d.classList.add("category-switch-handler"),
            Sn.setInputID(d, i, r, c, s);
            var u = t.querySelector("h4");
            qt(u).html(n),
            qt(u).attr("id", s),
            qt(h).append(t)
        })
    }
    ,
    kr);
    function kr() {
        this.El = "#onetrust-banner-sdk",
        this._saveBtn = null,
        this._settingsBtn = null,
        this._acceptBtn = null,
        this._rejectBtn = null,
        this._descriptCntr = null,
        this._btnsCntr = null,
        this._fourBtns = !1
    }
    var mr, br = (Pr.prototype.setHeaderConfig = function() {
        mr.setHeader(),
        mr.setSearchInput(),
        mr.setHeaderUIConsent();
        var e = mr.getGroupsForFilter();
        rr.setFilterListByGroup(e, !1)
    }
    ,
    Pr.prototype.filterVendorByString = function(e) {
        mr.searchQuery = e,
        mr.filterVendorByGroupOrQuery()
    }
    ,
    Pr.prototype.filterVendorByGroup = function(e) {
        mr.filterGroups = e,
        mr.filterVendorByGroupOrQuery()
    }
    ,
    Pr.prototype.showVSList = function() {
        mr.removeListeners(),
        mr.showEmptyResults(!1, ""),
        mr.clearUIElementsInMain(),
        mr.addVSList(Ht.getVendorsInDomain())
    }
    ,
    Pr.prototype.showEmptyResults = function(e, t) {
        if (e)
            this.setNoResultsContent(t);
        else {
            qt("#onetrust-pc-sdk " + Kt.P_Vendor_Content).removeClass("no-results");
            var o = qt("#onetrust-pc-sdk #no-results");
            o.length && o.remove()
        }
    }
    ,
    Pr.prototype.setNoResultsContent = function(e) {
        var t = qt("#onetrust-pc-sdk #no-results").el[0];
        if (!t) {
            var o = document.createElement("div")
              , n = document.createElement("p")
              , r = document.createTextNode(" did not match any vendors.")
              , i = document.createElement("span");
            return o.id = "no-results",
            i.id = "user-text",
            i.innerText = e,
            n.appendChild(i),
            n.appendChild(r),
            o.appendChild(n),
            qt("#onetrust-pc-sdk " + Kt.P_Vendor_Content).addClass("no-results"),
            qt("#vendor-search-handler").el[0].setAttribute("aria-describedby", o.id),
            qt("#onetrust-pc-sdk " + Kt.P_Vendor_Content).append(o)
        }
        t.querySelector("span").innerText = e
    }
    ,
    Pr.prototype.getGroupsFilter = function() {
        for (var e = [], t = 0, o = qt("#onetrust-pc-sdk .category-filter-handler").el; t < o.length; t++) {
            var n = o[t]
              , r = n.getAttribute("data-purposeid");
            n.checked && e.push(r)
        }
        return e
    }
    ,
    Pr.prototype.cancelFilter = function() {
        for (var e = 0, t = qt("#onetrust-pc-sdk .category-filter-handler").el; e < t.length; e++) {
            var o = t[e]
              , n = o.getAttribute("data-optanongroupid")
              , r = 0 <= Ht.filterByCategories.indexOf(n);
            Bt.setCheckedAttribute(null, o, r)
        }
        var i = mr.getGroupsFilter();
        mr.filterVendorByGroup(i)
    }
    ,
    Pr.prototype.clearFilter = function() {
        mr.searchQuery = "",
        mr.filterGroups = []
    }
    ,
    Pr.prototype.toggleVendors = function(r) {
        Ht.getVendorsInDomain().forEach(function(e, t) {
            if (!Xt.isAlwaysActiveGroup(e.groupRef)) {
                var o = document.getElementById("ot-vendor-id-" + t)
                  , n = document.getElementById("ot-vs-lst-id-" + t);
                ur.toggleVendorService(e.groupRef.CustomGroupId, t, r, o),
                ur.toggleVendorService(e.groupRef.CustomGroupId, t, r, n)
            }
        })
    }
    ,
    Pr.prototype.hideVendorList = function() {
        mr.removeListeners(),
        mr.clearUIElementsInMain()
    }
    ,
    Pr.prototype.addListeners = function() {
        qt("#onetrust-pc-sdk " + Kt.P_Vendor_Content + " .ot-vs-list .category-switch-handler").on("click", mr.toggleVendorHandler),
        qt("#onetrust-pc-sdk").on("click", ".ot-vs-list", Sr.onCategoryItemToggle.bind(this))
    }
    ,
    Pr.prototype.removeListeners = function() {
        document.querySelectorAll("#onetrust-pc-sdk .ot-vs-list .category-switch-handler").forEach(function(e) {
            return e.removeEventListener("click", Sr.toggleGroupORVendorHandler)
        });
        var e = document.querySelector("#onetrust-pc-sdk .ot-vs-list");
        null != e && e.removeEventListener("click", Sr.onCategoryItemToggle)
    }
    ,
    Pr.prototype.toggleVendorHandler = function(e) {
        Sr.toggleVendorFromListHandler(e),
        mr.checkAllowAllCheckedValue()
    }
    ,
    Pr.prototype.filterVendorByGroupOrQuery = function() {
        var o = new Map;
        Ht.getVendorsInDomain().forEach(function(e, t) {
            mr.checkVendorConditions(e) && o.set(t, e)
        }),
        mr.showEmptyResults(o.size <= 0, mr.searchQuery),
        mr.removeListeners(),
        mr.clearUIElementsInMain(),
        mr.addVSList(o)
    }
    ,
    Pr.prototype.checkVendorConditions = function(e) {
        return !("" !== mr.searchQuery && e.ServiceName.toLowerCase().indexOf(mr.searchQuery.toLowerCase()) < 0 || 0 < mr.filterGroups.length && mr.filterGroups.indexOf(e.groupRef.CustomGroupId) < 0)
    }
    ,
    Pr.prototype.addVSList = function(e) {
        var t = qt("#onetrust-pc-sdk " + Kt.P_Vendor_Content + " .ot-sdk-column")
          , o = ur.getVendorListEle(e);
        t.append(o),
        mr.addListeners()
    }
    ,
    Pr.prototype.getGroupsForFilter = function() {
        var t = new Map;
        return Ht.getVendorsInDomain().forEach(function(e) {
            t.has(e.groupRef.CustomGroupId) || t.set(e.groupRef.CustomGroupId, e.groupRef)
        }),
        Array.from(t.values())
    }
    ,
    Pr.prototype.clearUIElementsInMain = function() {
        qt("#onetrust-pc-sdk " + Kt.P_Vendor_Content + " ul" + Kt.P_Host_Cntr).html(""),
        qt("#onetrust-pc-sdk " + Kt.P_Vendor_Content + " ul" + Kt.P_Host_Cntr).hide(),
        qt("#onetrust-pc-sdk " + Kt.P_Vendor_Content + " ul" + Kt.P_Vendor_Container).html(""),
        qt("#onetrust-pc-sdk " + Kt.P_Vendor_Content + " ul" + Kt.P_Vendor_Container).hide();
        var e = qt("#onetrust-pc-sdk " + Kt.P_Vendor_Content + " .ot-vs-list");
        e && e.length && e.remove()
    }
    ,
    Pr.prototype.setHeader = function() {
        var e = Nt.VendorServiceConfig.PCVSListTitle
          , t = document.querySelector("#onetrust-pc-sdk " + Kt.P_Vendor_Title);
        t && (t.innerText = e)
    }
    ,
    Pr.prototype.setSearchInput = function() {
        var e = Nt.PCenterCookieListSearch
          , t = Nt.PCenterCookieSearchAriaLabel
          , o = qt("#onetrust-pc-sdk " + Kt.P_Vendor_Search_Input);
        o.el[0].placeholder = e,
        o.attr("aria-label", t)
    }
    ,
    Pr.prototype.setHeaderUIConsent = function() {
        var e;
        if (qt("#onetrust-pc-sdk " + Kt.P_Select_Cntr).addClass("ot-vnd-list-cnt"),
        qt("#onetrust-pc-sdk " + Kt.P_Select_Cntr + " .ot-sel-all").addClass("ot-vs-selc-all"),
        Nt.PCCategoryStyle === se.Toggle && (qt("#onetrust-pc-sdk " + Kt.P_Select_Cntr + " .ot-sel-all").addClass("ot-toggle-conf"),
        Nt.PCAccordionStyle === W.Caret && qt("#onetrust-pc-sdk " + Kt.P_Select_Cntr + " .ot-sel-all").addClass("ot-caret-conf")),
        qt("#onetrust-pc-sdk " + Kt.P_Leg_Select_All).hide(),
        qt("#onetrust-pc-sdk #" + Kt.P_Sel_All_Host_El).hide(),
        qt("#onetrust-pc-sdk " + Kt.P_Host_Cntr).hide(),
        qt(Kt.P_Vendor_List + " #select-all-text-container").hide(),
        qt("#onetrust-pc-sdk #" + Kt.P_Sel_All_Vendor_Leg_El).hide(),
        qt("#onetrust-pc-sdk " + Kt.P_Vendor_Container).show(),
        qt("#onetrust-pc-sdk " + Kt.P_Select_Cntr).show(),
        qt("#onetrust-pc-sdk #" + Kt.P_Sel_All_Vendor_Consent_El).show("inline-block"),
        qt("#onetrust-pc-sdk " + Kt.P_Vendor_List).removeClass(Kt.P_Host_UI),
        qt("#onetrust-pc-sdk " + Kt.P_Vendor_Content).removeClass(Kt.P_Host_Cnt),
        !document.querySelector("#onetrust-pc-sdk .ot-sel-all-chkbox .sel-all-hdr")) {
            var t = document.createElement("h4");
            t.className = "sel-all-hdr",
            t.textContent = (null === (e = Nt.VendorServiceConfig) || void 0 === e ? void 0 : e.PCVSAllowAllText) || "PCVSAllowAllText";
            var o = document.querySelector("#onetrust-pc-sdk .ot-sel-all-chkbox")
              , n = Nt.PCCategoryStyle === se.Checkbox ? "beforeend" : "afterbegin";
            o.insertAdjacentElement(n, t)
        }
        mr.checkAllowAllCheckedValue()
    }
    ,
    Pr.prototype.checkAllowAllCheckedValue = function() {
        var t = !0;
        Ht.vsConsent.forEach(function(e) {
            e || (t = !1)
        });
        var e = document.getElementById("#select-all-vendor-groups-handler");
        Bt.setCheckedAttribute(null, e, t)
    }
    ,
    Pr);
    function Pr() {
        this.searchQuery = "",
        this.filterGroups = []
    }
    var Sr, Ar = (Tr.prototype.initCookieSettingHandlers = function() {
        qt(document).on("click", ".optanon-show-settings, .optanon-toggle-display, .ot-sdk-show-settings, .ot-pc-handler", this.cookiesSettingsBoundListener)
    }
    ,
    Tr.prototype.initFlgtCkStgBtnEventHandlers = function() {
        qt(".ot-floating-button__open").on("click", Sr.floatingCookieSettingOpenBtnClicked),
        qt(".ot-floating-button__close").on("click", Sr.floatingCookieSettingCloseBtnClicked)
    }
    ,
    Tr.prototype.floatingCookieSettingOpenBtnClicked = function(e) {
        qt(Sr.fltgBtnSltr).addClass("ot-pc-open"),
        Nt.cookiePersistentLogo.includes("ot_guard_logo.svg") && qt(Sr.fltgBtnFSltr).attr("aria-hidden", "true"),
        qt(Sr.fltgBtnBSltr).attr("aria-hidden", ""),
        qt(Sr.fltgBtnFrontBtn).el[0].setAttribute("aria-label", ""),
        qt(Sr.fltgBtnFrontBtn).el[0].setAttribute("aria-hidden", !0),
        qt(Sr.fltgBtnBackBtn).el[0].setAttribute("aria-label", Nt.AriaClosePreferences),
        qt(Sr.fltgBtnBackBtn).el[0].setAttribute("aria-hidden", !1),
        Vo.triggerGoogleAnalyticsEvent(Go, zo),
        Sr.showCookieSettingsHandler(e)
    }
    ,
    Tr.prototype.floatingCookieSettingCloseBtnClicked = function(e) {
        qt(Sr.fltgBtnFrontBtn).el[0].setAttribute("aria-label", Nt.AriaOpenPreferences),
        qt(Sr.fltgBtnFrontBtn).el[0].setAttribute("aria-hidden", !1),
        qt(Sr.fltgBtnBackBtn).el[0].setAttribute("aria-label", ""),
        qt(Sr.fltgBtnBackBtn).el[0].setAttribute("aria-hidden", !0),
        e && (Vo.triggerGoogleAnalyticsEvent(Go, Ko),
        Sr.hideCookieSettingsHandler(e))
    }
    ,
    Tr.prototype.initialiseLegIntBtnHandlers = function() {
        qt(document).on("click", ".ot-obj-leg-btn-handler", Sr.onLegIntButtonClick),
        qt(document).on("click", ".ot-remove-objection-handler", Sr.onLegIntButtonClick)
    }
    ,
    Tr.prototype.initialiseAddtlVenHandler = function() {
        qt("#onetrust-pc-sdk #ot-addtl-venlst").on("click", Sr.selectVendorsGroupHandler),
        qt("#onetrust-pc-sdk #ot-selall-adtlven-handler").on("click", Sr.selAllAdtlVenHandler)
    }
    ,
    Tr.prototype.initializeGenVenHandlers = function() {
        qt("#onetrust-pc-sdk #ot-gn-venlst .ot-gnven-chkbox-handler").on("click", Sr.genVendorToggled),
        qt("#onetrust-pc-sdk #ot-gn-venlst .ot-gv-venbox").on("click", Sr.genVendorDetails),
        qt("#onetrust-pc-sdk #ot-selall-gnven-handler").on("click", Sr.selectAllGenVenHandler)
    }
    ,
    Tr.prototype.initialiseConsentNoticeHandlers = function() {
        var e = this
          , t = 37
          , o = 39;
        if (Ot.pcName === st && Sr.categoryMenuSwitchHandler(),
        qt("#onetrust-pc-sdk .onetrust-close-btn-handler").on("click", Sr.bannerCloseButtonHandler),
        qt("#onetrust-pc-sdk #accept-recommended-btn-handler").on("click", Ir.allowAllEventHandler.bind(this, !0)),
        qt("#onetrust-pc-sdk .ot-pc-refuse-all-handler").on("click", Ir.rejectAllEventHandler.bind(this, !0)),
        qt("#onetrust-pc-sdk #close-pc-btn-handler").on("click", Sr.hideCookieSettingsHandler),
        qt(document).on("keydown", function(e) {
            var t = document.getElementById("onetrust-pc-sdk")
              , o = "none" !== window.getComputedStyle(t).display;
            if (27 === e.keyCode && t && o) {
                var n = qt("#onetrust-pc-sdk " + Kt.P_Fltr_Modal).el[0];
                "block" === n.style.display || "0px" < n.style.width ? (Sr.closeFilter(),
                qt("#onetrust-pc-sdk #filter-btn-handler").focus()) : Nt.NoBanner && !Nt.ShowPreferenceCenterCloseButton || Sr.hideCookieSettingsHandler(),
                Sr.confirmPC()
            }
            (o && 32 === e.keyCode || "Space" === e.code || 13 === e.keyCode || "Enter" === e.code) && Mt.findUserType(e)
        }),
        qt("#onetrust-pc-sdk #vendor-close-pc-btn-handler").on("click", Sr.hideCookieSettingsHandler),
        qt("#onetrust-pc-sdk .category-switch-handler").on("click", Sr.toggleGroupORVendorHandler),
        qt("#onetrust-pc-sdk .cookie-subgroup-handler").on("click", Sr.toggleSubCategory),
        qt("#onetrust-pc-sdk .category-menu-switch-handler").on("keydown", function(e) {
            Ot.pcName === st && (e.keyCode !== t && e.keyCode !== o || (Nt.PCTemplateUpgrade ? Sr.changeSelectedTabV2(e) : Sr.changeSelectedTab(e)))
        }),
        qt("#onetrust-pc-sdk").on("click", Kt.P_Category_Item + " > input:first-child," + Kt.P_Category_Item + " > button:first-child", Sr.onCategoryItemToggle.bind(this)),
        (Nt.showCookieList || Ht.showGeneralVendors) && (qt("#onetrust-pc-sdk .category-host-list-handler").on("click", function(e) {
            Ht.showGeneralVendors && Nt.showCookieList ? Ht.cookieListType = X.HostAndGenVen : Ht.showGeneralVendors ? Ht.cookieListType = X.GenVen : Ht.cookieListType = X.Host,
            Sr.pcLinkSource = e.target,
            Sr.loadCookieList(e.target)
        }),
        Mt.isOptOutEnabled() ? (qt("#onetrust-pc-sdk #select-all-hosts-groups-handler").on("click", Sr.selectAllHostsGroupsHandler),
        qt("#onetrust-pc-sdk " + Kt.P_Host_Cntr).on("click", Sr.selectHostsGroupHandler)) : qt("#onetrust-pc-sdk " + Kt.P_Host_Cntr).on("click", Sr.toggleAccordionStatus)),
        Nt.IsIabEnabled && (qt("#onetrust-pc-sdk .category-vendors-list-handler").on("click", function(e) {
            Sr.pcLinkSource = e.target,
            Sr.showVendorsList(e.target)
        }),
        qt("#onetrust-pc-sdk " + Kt.P_Vendor_Container).on("click", Sr.selectVendorsGroupHandler),
        Nt.UseGoogleVendors || Sr.bindSelAllHandlers(),
        Sr.initialiseLegIntBtnHandlers()),
        Nt.IsIabEnabled || Nt.showCookieList || Ht.showGeneralVendors || Ht.showVendorService) {
            qt(document).on("click", ".back-btn-handler", Sr.backBtnHandler),
            qt("#onetrust-pc-sdk #vendor-search-handler").on("keyup", function(e) {
                var t = e.target.value.trim();
                Ht.showVendorService ? mr.filterVendorByString(t) : Sr.isCookieList ? Gn.searchHostList(t) : (Gn.loadVendorList(t, []),
                Nt.UseGoogleVendors && Gn.searchVendors(Gn.googleSearchSelectors, Ht.addtlVendorsList, oe.GoogleVendor, t),
                Ht.showGeneralVendors && Nt.GeneralVendors.length && Gn.searchVendors(Gn.genVendorSearchSelectors, Nt.GeneralVendors, oe.GeneralVendor, t)),
                Gn.playSearchStatus(Sr.isCookieList)
            }),
            qt("#onetrust-pc-sdk #filter-btn-handler").on("click", Sr.toggleVendorFiltersHandler),
            qt("#onetrust-pc-sdk #filter-apply-handler").on("click", Sr.applyFilterHandler),
            qt("#onetrust-pc-sdk " + Kt.P_Fltr_Modal).on("click", Sr.tglFltrOptionHandler),
            !It.isV2Template && Ot.pcName !== it || qt("#onetrust-pc-sdk #filter-cancel-handler").on("click", Sr.cancelFilterHandler),
            !It.isV2Template && Ot.pcName === it || qt("#onetrust-pc-sdk #clear-filters-handler").on("click", Sr.clearFiltersHandler),
            It.isV2Template ? qt("#onetrust-pc-sdk #filter-cancel-handler").on("keydown", function(e) {
                9 !== e.keyCode && "tab" !== e.code || e.shiftKey || (e.preventDefault(),
                qt("#onetrust-pc-sdk #clear-filters-handler").el[0].focus())
            }) : qt("#onetrust-pc-sdk #filter-apply-handler").on("keydown", function(e) {
                9 !== e.keyCode && "tab" !== e.code || e.shiftKey || (e.preventDefault(),
                qt("#onetrust-pc-sdk .category-filter-handler").el[0].focus())
            });
            var n = qt("#onetrust-pc-sdk .category-filter-handler").el;
            qt(n[0]).on("keydown", function(e) {
                9 !== e.keyCode && "tab" !== e.code || !e.shiftKey || (e.preventDefault(),
                qt("#onetrust-pc-sdk #filter-apply-handler").el[0].focus())
            })
        }
        Nt.NoBanner && (Nt.OnClickCloseBanner && document.body.addEventListener("click", Ir.bodyClickEvent),
        Nt.ScrollCloseBanner && window.addEventListener("scroll", Ir.scrollCloseBanner)),
        qt("#onetrust-pc-sdk .ot-gv-list-handler").on("click", function(t) {
            return c(e, void 0, void 0, function() {
                return C(this, function(e) {
                    return Ht.cookieListType = X.GenVen,
                    Sr.loadCookieList(t.target),
                    [2]
                })
            })
        }),
        Ht.showVendorService && (Sr.bindSelAllHandlers(),
        qt("#onetrust-pc-sdk .onetrust-vendors-list-handler").on("click", function() {
            return c(e, void 0, void 0, function() {
                return C(this, function(e) {
                    return [2, Sr.showVendorsList(null, !0)]
                })
            })
        }))
    }
    ,
    Tr.prototype.bindSelAllHandlers = function() {
        qt("#onetrust-pc-sdk #select-all-vendor-leg-handler").on("click", Sr.selectAllVendorsLegIntHandler),
        qt("#onetrust-pc-sdk #select-all-vendor-groups-handler").on("click", Sr.SelectAllVendorConsentHandler)
    }
    ,
    Tr.prototype.hideCookieSettingsHandler = function(e) {
        return void 0 === e && (e = window.event),
        Vo.triggerGoogleAnalyticsEvent(Go, Fo),
        Rn.hideConsentNoticeV2(),
        Sr.getResizeElement().removeEventListener("resize", Sr.setCenterLayoutFooterHeight),
        window.removeEventListener("resize", Sr.setCenterLayoutFooterHeight),
        !It.isV2Template && Ot.pcName !== it || Sr.closeFilter(!1),
        Ot.pcName === nt && qt("#onetrust-pc-sdk " + Kt.P_Content).removeClass("ot-hide"),
        Ir.hideVendorsList(),
        hn.csBtnGroup && (qt(Sr.fltgBtnSltr).removeClass("ot-pc-open"),
        Sr.floatingCookieSettingCloseBtnClicked(null)),
        Sr.confirmPC(e),
        Ir.resetConsent(),
        !1
    }
    ,
    Tr.prototype.selectAllHostsGroupsHandler = function(e) {
        var t = e.target.checked
          , o = qt("#onetrust-pc-sdk #" + Kt.P_Sel_All_Host_El).el[0]
          , n = o.classList.contains("line-through")
          , r = qt("#onetrust-pc-sdk .host-checkbox-handler").el;
        Bt.setCheckedAttribute("#select-all-hosts-groups-handler", null, t);
        for (var i = 0; i < r.length; i++)
            r[i].getAttribute("disabled") || Bt.setCheckedAttribute(null, r[i], t);
        Ht.optanonHostList.forEach(function(e) {
            fo.updateHostStatus(e, t)
        }),
        r.forEach(function(e) {
            go.updateGenVendorStatus(e.getAttribute("hostId"), t)
        }),
        n && o.classList.remove("line-through")
    }
    ,
    Tr.prototype.selectHostsGroupHandler = function(e) {
        Sr.toggleAccordionStatus(e);
        var t = e.target.getAttribute("hostId")
          , o = e.target.getAttribute("ckType")
          , n = e.target.checked;
        if (null !== t) {
            if (o === J.GenVendor) {
                var r = Nt.GeneralVendors.find(function(e) {
                    return e.VendorCustomId === t
                }).Name;
                Vo.triggerGoogleAnalyticsEvent(Go, n ? Yo : Xo, r + ": VEN_" + t),
                go.updateGenVendorStatus(t, n)
            } else {
                var i = Bt.findIndex(Ht.optanonHostList, function(e) {
                    return e.HostId === t
                })
                  , s = Ht.optanonHostList[i];
                Sr.toggleHostStatus(s, n)
            }
            Bt.setCheckedAttribute(null, e.target, n)
        }
    }
    ,
    Tr.prototype.onCategoryItemToggle = function(e) {
        e.stopPropagation(),
        "BUTTON" === e.target.tagName && (Ot.pcName === nt && this.setPcListContainerHeight(),
        Sr.toggleAccordionStatus(e))
    }
    ,
    Tr.prototype.toggleAccordionStatus = function(e) {
        var t = e.target;
        if (t && t.getAttribute("aria-expanded")) {
            var o = "true" === t.getAttribute("aria-expanded") ? "false" : "true";
            t.setAttribute("aria-expanded", o)
        }
    }
    ,
    Tr.prototype.toggleHostStatus = function(e, t) {
        Vo.triggerGoogleAnalyticsEvent(Go, t ? Qo : $o, e.HostName + ": H_" + e.HostId),
        fo.updateHostStatus(e, t)
    }
    ,
    Tr.prototype.toggleBannerOptions = function(e) {
        qt(".banner-option-input").each(function(e) {
            qt(e).el.setAttribute("aria-expanded", !1)
        }),
        Sr.toggleAccordionStatus(e)
    }
    ,
    Tr.prototype.bannerCloseButtonHandler = function(e) {
        if (e && e.target && e.target.className) {
            var t = e.target.className;
            if (-1 < t.indexOf("save-preference-btn-handler"))
                Ht.bannerCloseSource = f.ConfirmChoiceButton,
                Vo.triggerGoogleAnalyticsEvent(Go, Uo);
            else if (-1 < t.indexOf("banner-close-button")) {
                Ht.bannerCloseSource = f.BannerCloseButton;
                var o = No;
                -1 < t.indexOf("ot-close-link") && (o = Do,
                Ht.bannerCloseSource = f.ContinueWithoutAcceptingButton),
                Vo.triggerGoogleAnalyticsEvent(Go, o)
            } else
                -1 < t.indexOf("ot-bnr-save-handler") && (Ht.bannerCloseSource = f.BannerSaveSettings,
                Vo.triggerGoogleAnalyticsEvent(Go, Ho))
        }
        return Ir.hideVendorsList(),
        Ir.bannerCloseButtonHandler()
    }
    ,
    Tr.prototype.onLegIntButtonClick = function(e) {
        if (e) {
            var t = e.currentTarget
              , o = "true" === t.parentElement.getAttribute("is-vendor")
              , n = t.parentElement.getAttribute("data-group-id")
              , r = !t.classList.contains("ot-leg-int-enabled");
            if (o)
                Sr.onVendorToggle(n, D.LI);
            else {
                var i = Xt.getGroupById(n);
                i.Parent ? Sr.updateSubGroupToggles(i, r, !0) : Sr.updateGroupToggles(i, r, !0)
            }
            Sn.updateLegIntBtnElement(t.parentElement, r)
        }
    }
    ,
    Tr.prototype.updateGroupToggles = function(t, o, e) {
        fo.toggleGroupHosts(t, o),
        Ht.genVenOptOutEnabled && fo.toggleGroupGenVendors(t, o),
        t.IsLegIntToggle = e,
        Sn.toggleGrpStatus(t, o),
        t.SubGroups && t.SubGroups.length && (Ot.bannerName === et && It.moduleInitializer.IsSuppressPC && t.SubGroups.length ? t.SubGroups.forEach(function(e) {
            e.IsLegIntToggle = t.IsLegIntToggle,
            Sn.toggleGrpStatus(e, o),
            e.IsLegIntToggle = !1,
            fo.toggleGroupHosts(e, o),
            Ht.genVenOptOutEnabled && fo.toggleGroupGenVendors(e, o),
            ur.setVendorStateByGroup(e, o)
        }) : Sn.toogleAllSubGrpElements(t, o)),
        ur.setVendorStateByGroup(t, o),
        this.allowAllVisible(Sn.setAllowAllButton()),
        t.IsLegIntToggle = !1
    }
    ,
    Tr.prototype.updateSubGroupToggles = function(e, t, o) {
        fo.toggleGroupHosts(e, t),
        Ht.genVenOptOutEnabled && fo.toggleGroupGenVendors(e, t);
        var n = Xt.getGroupById(e.Parent);
        e.IsLegIntToggle = o,
        n.IsLegIntToggle = e.IsLegIntToggle;
        var r = Sn.isGroupActive(n);
        t ? (Sn.toggleGrpStatus(e, !0),
        Sn.isAllSubgroupsEnabled(n) && !r && (Sn.toggleGrpStatus(n, !0),
        fo.toggleGroupHosts(n, t),
        Ht.genVenOptOutEnabled && fo.toggleGroupGenVendors(n, t),
        Sn.toggleGroupHtmlElement(e, e.Parent + (e.IsLegIntToggle ? "-leg-out" : ""), !0))) : (Sn.toggleGrpStatus(e, !1),
        Sn.isAllSubgroupsDisabled(n) && r ? (Sn.toggleGrpStatus(n, !1),
        fo.toggleGroupHosts(n, t),
        Ht.genVenOptOutEnabled && fo.toggleGroupGenVendors(n, t),
        Sn.toggleGroupHtmlElement(e, e.Parent + (e.IsLegIntToggle ? "-leg-out" : ""), t)) : (Sn.toggleGrpStatus(n, !1),
        fo.toggleGroupHosts(n, !1),
        Ht.genVenOptOutEnabled && fo.toggleGroupGenVendors(n, t),
        Sn.toggleGroupHtmlElement(e, e.Parent + (e.IsLegIntToggle ? "-leg-out" : ""), !1))),
        this.allowAllVisible(Sn.setAllowAllButton()),
        e.IsLegIntToggle = !1,
        n.IsLegIntToggle = e.IsLegIntToggle
    }
    ,
    Tr.prototype.hideCategoryContainer = function(e) {
        void 0 === e && (e = !1);
        var t = Ot.pcName;
        this.isCookieList = e,
        Nt.PCTemplateUpgrade ? qt("#onetrust-pc-sdk " + Kt.P_Content).addClass("ot-hide") : qt("#onetrust-pc-sdk .ot-main-content").hide(),
        qt("#onetrust-pc-sdk " + Kt.P_Vendor_List).removeClass("ot-hide"),
        t !== it && t !== nt && qt("#onetrust-pc-sdk #close-pc-btn-handler.main").hide(),
        t === nt && Lt(qt("#onetrust-pc-sdk").el[0], 'height: "";', !0),
        Ht.showVendorService ? mr.setHeaderConfig() : (e ? Sr.setCookieListTemplate() : Sr.setVendorListTemplate(),
        rr.setFilterList(e))
    }
    ,
    Tr.prototype.setCookieListTemplate = function() {
        var e = It.isV2Template;
        qt(Kt.P_Vendor_List + " #select-all-text-container").show("inline-block"),
        qt("#onetrust-pc-sdk " + Kt.P_Host_Cntr).show(),
        Mt.isOptOutEnabled() ? qt("#onetrust-pc-sdk #" + Kt.P_Sel_All_Host_El).show("inline-block") : qt("#onetrust-pc-sdk #" + Kt.P_Sel_All_Host_El).hide(),
        qt("#onetrust-pc-sdk #" + Kt.P_Sel_All_Vendor_Leg_El).hide(),
        qt("#onetrust-pc-sdk " + Kt.P_Leg_Header).hide(),
        e || qt("#onetrust-pc-sdk " + Kt.P_Leg_Select_All).hide(),
        qt("#onetrust-pc-sdk #" + Kt.P_Sel_All_Vendor_Consent_El).hide(),
        qt("#onetrust-pc-sdk  " + Kt.P_Vendor_Container).hide(),
        (Nt.UseGoogleVendors || Ht.showGeneralVendors) && qt("#onetrust-pc-sdk .ot-acc-cntr").hide(),
        qt("#onetrust-pc-sdk " + Kt.P_Vendor_List).addClass(Kt.P_Host_UI),
        qt("#onetrust-pc-sdk " + Kt.P_Vendor_Content).addClass(Kt.P_Host_Cnt)
    }
    ,
    Tr.prototype.setVendorListTemplate = function() {
        qt("#onetrust-pc-sdk " + Kt.P_Vendor_Container).show(),
        qt("#onetrust-pc-sdk #" + Kt.P_Sel_All_Vendor_Consent_El).show("inline-block"),
        Nt.UseGoogleVendors && qt("#onetrust-pc-sdk .ot-acc-cntr").show(),
        Ot.legIntSettings.PAllowLI && "IAB2" === Ot.iabType ? (qt("#onetrust-pc-sdk " + Kt.P_Select_Cntr).show(It.isV2Template ? void 0 : "inline-block"),
        qt("#onetrust-pc-sdk " + Kt.P_Leg_Select_All).show("inline-block"),
        qt("#onetrust-pc-sdk #" + Kt.P_Sel_All_Vendor_Leg_El).show("inline-block"),
        qt(Kt.P_Vendor_List + " #select-all-text-container").hide(),
        Ot.legIntSettings.PShowLegIntBtn ? (qt("#onetrust-pc-sdk " + Kt.P_Leg_Header).hide(),
        qt("#onetrust-pc-sdk #" + Kt.P_Sel_All_Vendor_Leg_El).hide()) : qt("#onetrust-pc-sdk " + Kt.P_Leg_Header).show()) : (qt("#onetrust-pc-sdk " + Kt.P_Select_Cntr).show(),
        qt(Kt.P_Vendor_List + " #select-all-text-container").show("inline-block"),
        qt("#onetrust-pc-sdk " + Kt.P_Leg_Select_All).hide(),
        qt("#onetrust-pc-sdk #" + Kt.P_Sel_All_Vendor_Leg_El).hide()),
        qt("#onetrust-pc-sdk #" + Kt.P_Sel_All_Host_El).hide(),
        qt("#onetrust-pc-sdk " + Kt.P_Host_Cntr).hide(),
        qt("#onetrust-pc-sdk " + Kt.P_Vendor_List).removeClass(Kt.P_Host_UI),
        qt("#onetrust-pc-sdk " + Kt.P_Vendor_Content).removeClass(Kt.P_Host_Cnt)
    }
    ,
    Tr.prototype.showAllVendors = function(t) {
        return c(this, void 0, void 0, function() {
            return C(this, function(e) {
                switch (e.label) {
                case 0:
                    return [4, Sr.fetchAndSetupPC()];
                case 1:
                    return e.sent(),
                    Sr.showVendorsList(null, !0),
                    Ht.isPCVisible ? [3, 3] : [4, Sr.showCookieSettingsHandler(t)];
                case 2:
                    e.sent(),
                    e.label = 3;
                case 3:
                    return [2]
                }
            })
        })
    }
    ,
    Tr.prototype.fetchAndSetupPC = function() {
        return c(this, void 0, void 0, function() {
            var t, o;
            return C(this, function(e) {
                switch (e.label) {
                case 0:
                    return It.moduleInitializer.IsSuppressPC && 0 === qt("#onetrust-pc-sdk").length ? [4, dn.getPcContent()] : [3, 2];
                case 1:
                    t = e.sent(),
                    hn.preferenceCenterGroup = {
                        name: t.name,
                        html: atob(t.html),
                        css: t.css
                    },
                    It.isV2Template = Nt.PCTemplateUpgrade && /otPcPanel|otPcCenter|otPcTab/.test(t.name),
                    (o = document.getElementById("onetrust-style")).innerHTML += hn.preferenceCenterGroup.css,
                    o.innerHTML += ar.addCustomPreferenceCenterCSS(),
                    gr.insertPcHtml(),
                    Sr.initialiseConsentNoticeHandlers(),
                    Nt.IsIabEnabled && Gn.InitializeVendorList(),
                    e.label = 2;
                case 2:
                    return [2]
                }
            })
        })
    }
    ,
    Tr.prototype.setVendorContent = function() {
        qt("#onetrust-pc-sdk #filter-count").text(Ht.filterByIABCategories.length.toString()),
        Gn.loadVendorList("", Ht.filterByIABCategories),
        Nt.UseGoogleVendors && (Ht.vendorDomInit ? Gn.resetAddtlVendors() : (Gn.initGoogleVendors(),
        qt("#onetrust-pc-sdk").on("click", ".ot-acc-cntr > button", Sr.toggleAccordionStatus.bind(this)))),
        Ht.vendorDomInit || (Ht.vendorDomInit = !0,
        Sr.initialiseLegIntBtnHandlers(),
        Nt.UseGoogleVendors && (Sr.initialiseAddtlVenHandler(),
        Sr.bindSelAllHandlers())),
        Ht.showGeneralVendors && !Ht.genVendorDomInit && (Ht.genVendorDomInit = !0,
        Gn.initGenVendors(),
        Sr.initializeGenVenHandlers(),
        Nt.UseGoogleVendors || (Sr.bindSelAllHandlers(),
        qt("#onetrust-pc-sdk").on("click", ".ot-acc-cntr > button", Sr.toggleAccordionStatus.bind(this))))
    }
    ,
    Tr.prototype.showVendorsList = function(e, t) {
        if (void 0 === t && (t = !1),
        Sr.hideCategoryContainer(!1),
        Ht.showVendorService)
            mr.showVSList();
        else {
            if (!t) {
                var o = e.getAttribute("data-parent-id");
                if (o) {
                    var n = Xt.getGroupById(o);
                    if (n) {
                        var r = y(n.SubGroups, [n]).reduce(function(e, t) {
                            return -1 < bt.indexOf(t.Type) && e.push(t.CustomGroupId),
                            e
                        }, []);
                        Ht.filterByIABCategories = y(Ht.filterByIABCategories, r)
                    }
                }
            }
            Sr.setVendorContent(),
            En.updateFilterSelection(!1)
        }
        return Ht.pcLayer = _.VendorList,
        e && mn.setPCFocus(mn.getPCElements()),
        this.setSearchInputFocus(),
        !1
    }
    ,
    Tr.prototype.loadCookieList = function(e) {
        Ht.filterByCategories = [],
        Sr.hideCategoryContainer(!0);
        var t = e && e.getAttribute("data-parent-id");
        if (t) {
            var o = Xt.getGroupById(t);
            Ht.filterByCategories.push(t),
            o.SubGroups.length && o.SubGroups.forEach(function(e) {
                if (-1 === bt.indexOf(e.Type)) {
                    var t = e.CustomGroupId;
                    Ht.filterByCategories.indexOf(t) < 0 && Ht.filterByCategories.push(t)
                }
            })
        }
        return Gn.loadHostList("", Ht.filterByCategories),
        qt("#onetrust-pc-sdk #filter-count").text(Ht.filterByCategories.length.toString()),
        En.updateFilterSelection(!0),
        Ht.pcLayer = _.CookieList,
        mn.setPCFocus(mn.getPCElements()),
        this.setSearchInputFocus(),
        !1
    }
    ,
    Tr.prototype.selectAllVendorsLegIntHandler = function(e) {
        var t = qt("#onetrust-pc-sdk #" + Kt.P_Sel_All_Vendor_Leg_El).el[0]
          , o = t.classList.contains("line-through")
          , n = qt(Kt.P_Vendor_Container + ' li:not([style="display: none;"]) .vendor-leg-checkbox-handler').el
          , r = e.target.checked
          , i = {};
        Ht.vendors.selectedLegIntVendors.map(function(e, t) {
            i[e.split(":")[0]] = t
        });
        for (var s = 0; s < n.length; s++) {
            Bt.setCheckedAttribute(null, n[s], r),
            Nt.PCShowConsentLabels && (n[s].parentElement.querySelector(".ot-label-status").innerHTML = r ? Nt.PCActiveText : Nt.PCInactiveText);
            var a = n[s].getAttribute("leg-vendorid")
              , l = i[a];
            void 0 === l && (l = a),
            Ht.vendors.selectedLegIntVendors[l] = a + ":" + r
        }
        o && t.classList.remove("line-through"),
        Bt.setCheckedAttribute(null, e.target, r)
    }
    ,
    Tr.prototype.selAllAdtlVenHandler = function(e) {
        for (var t = qt("#onetrust-pc-sdk #ot-selall-adtlvencntr").el[0], o = t.classList.contains("line-through"), n = qt("#onetrust-pc-sdk .ot-addtlven-chkbox-handler").el, r = e.target.checked, i = 0; i < n.length; i++)
            Bt.setCheckedAttribute(null, n[i], r),
            Nt.PCShowConsentLabels && (n[i].parentElement.querySelector(".ot-label-status").innerHTML = r ? Nt.PCActiveText : Nt.PCInactiveText);
        r ? Nt.UseGoogleVendors && Object.keys(Ht.addtlVendorsList).forEach(function(e) {
            Ht.addtlVendors.vendorSelected[e] = !0
        }) : Ht.addtlVendors.vendorSelected = {},
        o && t.classList.remove("line-through")
    }
    ,
    Tr.prototype.selectAllGenVenHandler = function(e) {
        var t = e.target.checked;
        Sr.selectAllHandler({
            selAllEl: "#onetrust-pc-sdk #ot-selall-gnvencntr",
            vendorBoxes: "#onetrust-pc-sdk .ot-gnven-chkbox-handler"
        }, "genven", t)
    }
    ,
    Tr.prototype.selectAllHandler = function(e, t, o) {
        for (var n = qt(e.selAllEl).el[0], r = n.classList.contains("line-through"), i = qt(e.vendorBoxes).el, s = 0; s < i.length; s++)
            "genven" === t && !o && Ht.alwaysActiveGenVendors.includes(i[s].getAttribute("gn-vid")) ? (Bt.setDisabledAttribute(null, i[s], !0),
            Bt.setCheckedAttribute(null, i[s], !0)) : Bt.setCheckedAttribute(null, i[s], o),
            Nt.PCShowConsentLabels && (i[s].parentElement.querySelector(".ot-label-status").innerHTML = o ? Nt.PCActiveText : Nt.PCInactiveText);
        o ? "googleven" === t && Nt.UseGoogleVendors ? Object.keys(Ht.addtlVendorsList).forEach(function(e) {
            Ht.addtlVendors.vendorSelected[e] = !0
        }) : "genven" === t && Ht.showGeneralVendors && Nt.GeneralVendors.forEach(function(e) {
            Ht.genVendorsConsent[e.VendorCustomId] = !0
        }) : "googleven" === t ? Ht.addtlVendors.vendorSelected = {} : (Ht.genVendorsConsent = {},
        Ht.alwaysActiveGenVendors.forEach(function(e) {
            Ht.genVendorsConsent[e] = !0
        })),
        r && n.classList.remove("line-through")
    }
    ,
    Tr.prototype.SelectAllVendorConsentHandler = function(e) {
        var t = e.target.checked;
        if (Ht.showVendorService)
            mr.toggleVendors(t);
        else {
            var o = qt("#onetrust-pc-sdk #" + Kt.P_Sel_All_Vendor_Consent_El).el[0]
              , n = o.classList.contains("line-through")
              , r = qt(Kt.P_Vendor_Container + ' li:not([style="display: none;"]) .vendor-checkbox-handler').el
              , i = {};
            Ht.vendors.selectedVendors.map(function(e, t) {
                i[e.split(":")[0]] = t
            });
            for (var s = 0; s < r.length; s++) {
                Bt.setCheckedAttribute(null, r[s], t),
                Nt.PCShowConsentLabels && (r[s].parentElement.querySelector(".ot-label-status").innerHTML = t ? Nt.PCActiveText : Nt.PCInactiveText);
                var a = r[s].getAttribute("vendorid")
                  , l = i[a];
                void 0 === l && (l = a),
                Ht.vendors.selectedVendors[l] = a + ":" + t
            }
            n && o.classList.remove("line-through")
        }
        Bt.setCheckedAttribute(null, e.target, t)
    }
    ,
    Tr.prototype.onVendorToggle = function(n, e) {
        var t = Ht.vendors
          , o = Ht.addtlVendors
          , r = e === D.LI ? t.selectedLegIntVendors : e === D.AddtlConsent ? [] : t.selectedVendors
          , i = !1
          , s = Number(n);
        r.some(function(e, t) {
            var o = e.split(":");
            if (o[0] === n)
                return s = t,
                i = "true" === o[1],
                !0
        }),
        e === D.LI ? (Vo.triggerGoogleAnalyticsEvent(Go, i ? nn : rn, t.list.find(function(e) {
            return e.vendorId === n
        }).vendorName + ": IABV2_" + n),
        t.selectedLegIntVendors[s] = n + ":" + !i,
        Ot.legIntSettings.PShowLegIntBtn || Gn.vendorLegIntToggleEvent()) : e === D.AddtlConsent ? (o.vendorSelected[n] ? delete o.vendorSelected[n] : o.vendorSelected[n] = !0,
        Gn.venAdtlSelAllTglEvent()) : (Vo.triggerGoogleAnalyticsEvent(Go, i ? on : tn, t.list.find(function(e) {
            return e.vendorId === n
        }).vendorName + ": IABV2_" + n),
        t.selectedVendors[s] = n + ":" + !i,
        Gn.vendorsListEvent())
    }
    ,
    Tr.prototype.onVendorDisclosure = function(n) {
        return c(this, void 0, void 0, function() {
            var t, o;
            return C(this, function(e) {
                switch (e.label) {
                case 0:
                    return (t = Ht.discVendors)[n].isFetched ? [3, 2] : (t[n].isFetched = !0,
                    [4, dn.getStorageDisclosure(t[n].disclosureUrl)]);
                case 1:
                    o = e.sent(),
                    Gn.updateVendorDisclosure(n, o),
                    e.label = 2;
                case 2:
                    return [2]
                }
            })
        })
    }
    ,
    Tr.prototype.tglFltrOptionHandler = function(e) {
        e && e.target.classList.contains("category-filter-handler") && Bt.setCheckedAttribute(null, e.target, e.target.checked)
    }
    ,
    Tr.prototype.selectVendorsGroupHandler = function(e) {
        Sr.toggleAccordionStatus(e);
        var t = e.target.getAttribute("leg-vendorid")
          , o = e.target.getAttribute("vendorid")
          , n = e.target.getAttribute("addtl-vid")
          , r = e.target.getAttribute("disc-vid");
        t ? Sr.onVendorToggle(t, D.LI) : o ? Sr.onVendorToggle(o, D.Consent) : n && Sr.onVendorToggle(n, D.AddtlConsent),
        r && Sr.onVendorDisclosure(r),
        (t || o || n) && (Bt.setCheckedAttribute(null, e.target, e.target.checked),
        Nt.PCShowConsentLabels && (e.target.parentElement.querySelector(".ot-label-status").innerHTML = e.target.checked ? Nt.PCActiveText : Nt.PCInactiveText))
    }
    ,
    Tr.prototype.toggleVendorFiltersHandler = function() {
        var e = !1
          , t = qt("#onetrust-pc-sdk " + Kt.P_Fltr_Modal).el[0];
        switch (Ot.pcName) {
        case rt:
        case ot:
        case nt:
        case st:
            if (e = "block" === t.style.display)
                Sr.closeFilter();
            else {
                var o = qt("#onetrust-pc-sdk " + Kt.P_Triangle).el[0];
                qt(o).attr("style", "display: block;"),
                qt(t).attr("style", "display: block;");
                var n = Array.prototype.slice.call(t.querySelectorAll("[href], input, button"));
                mn.setPCFocus(n)
            }
            break;
        case it:
            896 < window.innerWidth || 896 < window.screen.height ? Lt(t, "width: 400px;", !0) : Lt(t, "height: 100%; width: 100%;"),
            t.querySelector(".ot-checkbox input").focus();
            break;
        default:
            return
        }
        It.isV2Template && !e && (qt("#onetrust-pc-sdk").addClass("ot-shw-fltr"),
        qt("#onetrust-pc-sdk .ot-fltr-scrlcnt").el[0].scrollTop = 0)
    }
    ,
    Tr.prototype.clearFiltersHandler = function() {
        Sr.setAriaLabelforButtonInFilter(Nt.PCenterFilterClearedAria);
        for (var e = qt("#onetrust-pc-sdk " + Kt.P_Fltr_Modal + " input").el, t = 0; t < e.length; t++)
            Bt.setCheckedAttribute(null, e[t], !1);
        Sr.isCookieList ? Ht.filterByCategories = [] : Ht.filterByIABCategories = []
    }
    ,
    Tr.prototype.cancelFilterHandler = function() {
        Ht.showVendorService ? mr.cancelFilter() : Sr.isCookieList ? En.cancelHostFilter() : Gn.cancelVendorFilter(),
        Sr.closeFilter(),
        qt("#onetrust-pc-sdk #filter-btn-handler").focus()
    }
    ,
    Tr.prototype.applyFilterHandler = function() {
        var e;
        Sr.setAriaLabelforButtonInFilter(Nt.PCenterFilterAppliedAria),
        Ht.showVendorService ? (e = mr.getGroupsFilter(),
        mr.filterVendorByGroup(e)) : Sr.isCookieList ? (e = En.updateHostFilterList(),
        Gn.loadHostList("", e)) : (e = Gn.updateVendorFilterList(),
        Gn.loadVendorList("", e)),
        qt("#onetrust-pc-sdk #filter-count").text(String(e.length)),
        Sr.closeFilter(),
        qt("#onetrust-pc-sdk #filter-btn-handler").focus()
    }
    ,
    Tr.prototype.setAriaLabelforButtonInFilter = function(e) {
        var t = document.querySelector("#onetrust-pc-sdk span[aria-live]");
        t || ((t = document.createElement("span")).classList.add("ot-scrn-rdr"),
        t.setAttribute("aria-atomic", "true"),
        document.getElementById("onetrust-pc-sdk").appendChild(t)),
        t.setAttribute("aria-atomic", "true"),
        t.setAttribute("aria-relevant", "additions"),
        t.setAttribute("aria-live", "assertive"),
        t.setAttribute("aria-label", e),
        Sr.timeCallback && clearTimeout(Sr.timeCallback),
        Sr.timeCallback = setTimeout(function() {
            Sr.timeCallback = null,
            t.setAttribute("aria-label", "")
        }, 900)
    }
    ,
    Tr.prototype.setPcListContainerHeight = function() {
        qt("#onetrust-pc-sdk " + Kt.P_Content).el[0].classList.contains("ot-hide") ? Lt(qt("#onetrust-pc-sdk").el[0], 'height: "";', !0) : setTimeout(function() {
            var e = window.innerHeight;
            768 <= window.innerWidth && 600 <= window.innerHeight && (e = .8 * window.innerHeight),
            !qt("#onetrust-pc-sdk " + Kt.P_Content).el[0].scrollHeight || qt("#onetrust-pc-sdk " + Kt.P_Content).el[0].scrollHeight >= e ? Lt(qt("#onetrust-pc-sdk").el[0], "height: " + e + "px;", !0) : Lt(qt("#onetrust-pc-sdk").el[0], "height: auto;", !0)
        })
    }
    ,
    Tr.prototype.changeSelectedTab = function(e) {
        var t, o = qt("#onetrust-pc-sdk .category-menu-switch-handler"), n = 0, r = qt(o.el[0]);
        o.each(function(e, t) {
            qt(e).el.classList.contains(Kt.P_Active_Menu) && (n = t,
            qt(e).el.classList.remove(Kt.P_Active_Menu),
            r = qt(e))
        }),
        e.keyCode === B.RightArrow ? t = n + 1 >= o.el.length ? qt(o.el[0]) : qt(o.el[n + 1]) : e.keyCode === B.LeftArrow && (t = qt(n - 1 < 0 ? o.el[o.el.length - 1] : o.el[n - 1])),
        this.tabMenuToggle(t, r)
    }
    ,
    Tr.prototype.changeSelectedTabV2 = function(e) {
        var t, o = e.target.parentElement;
        e.keyCode === B.RightArrow ? t = o.nextElementSibling || o.parentElement.firstChild : e.keyCode === B.LeftArrow && (t = o.previousElementSibling || o.parentElement.lastChild);
        var n = t.querySelector(".category-menu-switch-handler");
        n.focus(),
        this.groupTabClick(n)
    }
    ,
    Tr.prototype.categoryMenuSwitchHandler = function() {
        for (var t = this, e = qt("#onetrust-pc-sdk .category-menu-switch-handler").el, o = 0; o < e.length; o++)
            e[o].addEventListener("click", this.groupTabClick),
            e[o].addEventListener("keydown", function(e) {
                if (32 === e.keyCode || "space" === e.code)
                    return t.groupTabClick(e.currentTarget),
                    e.preventDefault(),
                    !1
            })
    }
    ,
    Tr.prototype.groupTabClick = function(e) {
        var t = qt("#onetrust-pc-sdk " + Kt.P_Grp_Container).el[0]
          , o = t.querySelector("." + Kt.P_Active_Menu)
          , n = e.currentTarget || e
          , r = n.getAttribute("aria-controls");
        o.setAttribute("tabindex", -1),
        o.setAttribute("aria-selected", !1),
        o.classList.remove(Kt.P_Active_Menu),
        t.querySelector(Kt.P_Desc_Container + ":not(.ot-hide)").classList.add("ot-hide"),
        t.querySelector("#" + r).classList.remove("ot-hide"),
        n.setAttribute("tabindex", 0),
        n.setAttribute("aria-selected", !0),
        n.classList.add(Kt.P_Active_Menu)
    }
    ,
    Tr.prototype.tabMenuToggle = function(e, t) {
        e.el.setAttribute("tabindex", 0),
        e.el.setAttribute("aria-selected", !0),
        t.el.setAttribute("tabindex", -1),
        t.el.setAttribute("aria-selected", !1),
        e.focus(),
        t.el.parentElement.parentElement.querySelector("" + Kt.P_Desc_Container).classList.add("ot-hide"),
        e.el.parentElement.parentElement.querySelector("" + Kt.P_Desc_Container).classList.remove("ot-hide"),
        e.el.classList.add(Kt.P_Active_Menu)
    }
    ,
    Tr.prototype.closeFilter = function(e) {
        if (void 0 === e && (e = !0),
        !Rn.checkIfPcSdkContainerExist()) {
            var t = qt("#onetrust-pc-sdk " + Kt.P_Fltr_Modal).el[0]
              , o = qt("#onetrust-pc-sdk " + Kt.P_Triangle).el[0];
            Ot.pcName === it ? 896 < window.innerWidth || 896 < window.screen.height ? Lt(t, "width: 0;", !0) : Lt(t, "height: 0;") : Lt(t, "display: none;"),
            o && qt(o).attr("style", "display: none;"),
            It.isV2Template && qt("#onetrust-pc-sdk").removeClass("ot-shw-fltr"),
            e && mn.setFirstAndLast(mn.getPCElements())
        }
    }
    ,
    Tr.prototype.setBackButtonFocus = function() {
        qt("#onetrust-pc-sdk .back-btn-handler").el[0].focus()
    }
    ,
    Tr.prototype.setSearchInputFocus = function() {
        qt("#onetrust-pc-sdk #vendor-search-handler").el[0].focus()
    }
    ,
    Tr.prototype.setCenterLayoutFooterHeight = function() {
        var e = Sr.pc;
        if (Sr.setMainContentHeight(),
        Ot.pcName === st && e) {
            var t = e.querySelectorAll("" + Kt.P_Desc_Container)
              , o = e.querySelectorAll("li .category-menu-switch-handler");
            if (!e.querySelector(".category-menu-switch-handler + " + Kt.P_Desc_Container) && window.innerWidth < 640)
                for (var n = 0; n < t.length; n++)
                    o[n].insertAdjacentElement("afterend", t[n]);
            else
                e.querySelector(".category-menu-switch-handler + " + Kt.P_Desc_Container) && 640 < window.innerWidth && qt(e.querySelector(".ot-tab-desc")).append(t)
        }
    }
    ,
    Tr.prototype.setMainContentHeight = function() {
        var e = this.pc
          , t = e.querySelector(".ot-pc-footer")
          , o = e.querySelector(".ot-pc-header")
          , n = e.querySelectorAll(".ot-pc-footer button")
          , r = n[n.length - 1]
          , i = Nt.PCLayout;
        if (e.classList.remove("ot-ftr-stacked"),
        n[0] && r && 1 < Math.abs(n[0].offsetTop - r.offsetTop) && e.classList.add("ot-ftr-stacked"),
        !Nt.PCTemplateUpgrade && !i.Center) {
            var s = e.clientHeight - t.clientHeight - o.clientHeight - 3;
            if (Nt.PCTemplateUpgrade && !i.Tab && Nt.PCenterVendorListDescText) {
                var a = qt("#vdr-lst-dsc").el;
                s = s - (a.length && a[0].clientHeight) - 10
            }
            Lt(e.querySelector("" + Kt.P_Vendor_List), "height: " + s + "px;", !0)
        }
        var l = e.querySelector("" + Kt.P_Content);
        if (Nt.PCTemplateUpgrade && i.Center) {
            var c = 600 < window.innerWidth && 475 < window.innerHeight;
            if (!this.pcBodyHeight && c && (this.pcBodyHeight = l.scrollHeight),
            c) {
                var d = this.pcBodyHeight + t.clientHeight + o.clientHeight + 20;
                d > .8 * window.innerHeight || 0 === this.pcBodyHeight ? Lt(e, "height: " + .8 * window.innerHeight + "px;", !0) : Lt(e, "height: " + d + "px;", !0)
            } else
                Lt(e, "height: 100%;", !0)
        } else
            Lt(e.querySelector("" + Kt.P_Content), "height: " + (e.clientHeight - t.clientHeight - o.clientHeight - 3) + "px;", !0)
    }
    ,
    Tr.prototype.allowAllVisible = function(e) {
        e !== this.allowVisible && Nt.PCLayout.Tab && Nt.PCTemplateUpgrade && (this.pc && this.setMainContentHeight(),
        this.allowVisible = e)
    }
    ,
    Tr.prototype.restorePc = function() {
        Ht.pcLayer === _.CookieList ? (Sr.hideCategoryContainer(!0),
        Gn.loadHostList("", Ht.filterByCategories),
        qt("#onetrust-pc-sdk #filter-count").text(Ht.filterByCategories.length.toString())) : Ht.pcLayer === _.VendorList && (Sr.hideCategoryContainer(!1),
        Sr.setVendorContent()),
        Ht.isPCVisible = !1,
        Sr.toggleInfoDisplay(),
        Ht.pcLayer !== _.VendorList && Ht.pcLayer !== _.CookieList || (En.updateFilterSelection(Ht.pcLayer === _.CookieList),
        Sr.setBackButtonFocus(),
        mn.setPCFocus(mn.getPCElements()))
    }
    ,
    Tr.prototype.toggleInfoDisplay = function() {
        return c(this, void 0, void 0, function() {
            var t, o;
            return C(this, function(e) {
                switch (e.label) {
                case 0:
                    return hn.csBtnGroup && (qt(Sr.fltgBtnSltr).addClass("ot-pc-open"),
                    Sr.otGuardLogoPromise.then(function() {
                        Nt.cookiePersistentLogo.includes("ot_guard_logo.svg") && qt(Sr.fltgBtnFSltr).attr("aria-hidden", "true")
                    }),
                    qt(Sr.fltgBtnBSltr).attr("aria-hidden", "")),
                    [4, Sr.fetchAndSetupPC()];
                case 1:
                    return e.sent(),
                    Ot.pcName === nt && this.setPcListContainerHeight(),
                    void 0 !== Ht.pcLayer && Ht.pcLayer !== _.Banner || (Ht.pcLayer = _.PrefCenterHome),
                    t = qt("#onetrust-pc-sdk").el[0],
                    qt(".onetrust-pc-dark-filter").el[0].removeAttribute("style"),
                    t.removeAttribute("style"),
                    Ht.isPCVisible || (Rn.showConsentNotice(),
                    Ht.isPCVisible = !0,
                    Nt.PCTemplateUpgrade && (this.pc = t,
                    o = t.querySelector("#accept-recommended-btn-handler"),
                    this.allowVisible = o && 0 < o.clientHeight,
                    this.setCenterLayoutFooterHeight(),
                    Sr.getResizeElement().addEventListener("resize", Sr.setCenterLayoutFooterHeight),
                    window.addEventListener("resize", Sr.setCenterLayoutFooterHeight))),
                    window.dispatchEvent(new CustomEvent("OneTrustPCLoaded",{
                        OneTrustPCLoaded: "yes"
                    })),
                    Sr.captureInitialConsent(),
                    [2]
                }
            })
        })
    }
    ,
    Tr.prototype.close = function(e) {
        Nt.BCloseButtonType === de.Link ? Ht.bannerCloseSource = f.ContinueWithoutAcceptingButton : Ht.bannerCloseSource = f.BannerCloseButton,
        Ir.bannerCloseButtonHandler(e),
        Sr.getResizeElement().removeEventListener("resize", Sr.setCenterLayoutFooterHeight),
        window.removeEventListener("resize", Sr.setCenterLayoutFooterHeight)
    }
    ,
    Tr.prototype.closePreferenceCenter = function(e) {
        e && e.preventDefault(),
        window.location.href = "http://otsdk//consentChanged"
    }
    ,
    Tr.prototype.initializeAlartHtmlAndHandler = function() {
        Ht.skipAddingHTML = 0 < qt("#onetrust-banner-sdk").length,
        Ht.skipAddingHTML || fr.insertAlertHtml(),
        this.initialiseAlertHandlers()
    }
    ,
    Tr.prototype.initialiseAlertHandlers = function() {
        var e = this;
        fr.showBanner(),
        Nt.ForceConsent && !Mt.isCookiePolicyPage(Nt.AlertNoticeText) && qt(".onetrust-pc-dark-filter").removeClass("ot-hide").css("z-index:2147483645;"),
        Nt.OnClickCloseBanner && document.body.addEventListener("click", Ir.bodyClickEvent),
        Nt.ScrollCloseBanner && (window.addEventListener("scroll", Ir.scrollCloseBanner),
        qt(document).on("click", ".onetrust-close-btn-handler", Ir.rmScrollAndClickBodyEvents),
        qt(document).on("click", "#onetrust-accept-btn-handler", Ir.rmScrollAndClickBodyEvents),
        qt(document).on("click", "#accept-recommended-btn-handler", Ir.rmScrollAndClickBodyEvents)),
        (Nt.IsIabEnabled || Nt.UseGoogleVendors || Ht.showGeneralVendors || Ht.showVendorService) && qt(document).on("click", ".onetrust-vendors-list-handler", Sr.showAllVendors),
        Nt.FloatingRoundedIcon && qt("#onetrust-banner-sdk #onetrust-cookie-btn").on("click", function(e) {
            Ht.pcSource = e.currentTarget,
            Sr.showCookieSettingsHandler(e)
        }),
        qt("#onetrust-banner-sdk .onetrust-close-btn-handler, #onetrust-banner-sdk .ot-bnr-save-handler").on("click", Sr.bannerCloseButtonHandler),
        qt("#onetrust-banner-sdk #onetrust-pc-btn-handler").on("click", Sr.showCookieSettingsHandler),
        qt("#onetrust-banner-sdk #onetrust-accept-btn-handler").on("click", Ir.allowAllEventHandler.bind(this, !1)),
        qt("#onetrust-banner-sdk #onetrust-reject-all-handler").on("click", Ir.rejectAllEventHandler.bind(this, !1)),
        qt("#onetrust-banner-sdk .banner-option-input").on("click", Ot.bannerName === $e ? Sr.toggleBannerOptions : Sr.toggleAccordionStatus),
        qt("#onetrust-banner-sdk .ot-gv-list-handler").on("click", function(t) {
            return c(e, void 0, void 0, function() {
                return C(this, function(e) {
                    switch (e.label) {
                    case 0:
                        return Ht.cookieListType = X.GenVen,
                        [4, Sr.fetchAndSetupPC()];
                    case 1:
                        return e.sent(),
                        Sr.loadCookieList(t.target),
                        Sr.showCookieSettingsHandler(t),
                        [2]
                    }
                })
            })
        }),
        qt("#onetrust-banner-sdk .category-switch-handler").on("click", Sr.toggleBannerCategory),
        qt("#onetrust-banner-sdk").on("keydown", function(e) {
            9 !== e.keyCode && "tab" !== e.code || mn.handleBannerFocus(e, e.shiftKey),
            32 !== e.keyCode && "Space" !== e.code && 13 !== e.keyCode && "Enter" !== e.code || Mt.findUserType(e)
        })
    }
    ,
    Tr.prototype.getResizeElement = function() {
        var e = document.querySelector("#onetrust-pc-sdk .ot-text-resize");
        return e ? e.contentWindow || e : document
    }
    ,
    Tr.prototype.insertCookieSettingText = function(e) {
        var t, o;
        void 0 === e && (e = !1);
        for (var n = Nt.CookieSettingButtonText, r = qt(".ot-sdk-show-settings").el, i = qt(".optanon-toggle-display").el, s = 0; s < r.length; s++)
            qt(r[s]).text(n),
            qt(i[s]).text(n);
        e ? (null !== (t = document.querySelector(".ot-sdk-show-settings")) && void 0 !== t && t.addEventListener("click", this.cookiesSettingsBoundListener),
        null !== (o = document.querySelector(".optanon-toggle-display")) && void 0 !== o && o.addEventListener("click", this.cookiesSettingsBoundListener)) : Sr.initCookieSettingHandlers()
    }
    ,
    Tr.prototype.genVendorToggled = function(e) {
        var t = e.target.getAttribute("gn-vid");
        go.updateGenVendorStatus(t, e.target.checked);
        var o = Nt.GeneralVendors.find(function(e) {
            return e.VendorCustomId === t
        }).Name;
        Vo.triggerGoogleAnalyticsEvent(Go, e.target.checked ? Yo : Xo, o + ": VEN_" + t),
        Gn.genVenSelectAllTglEvent()
    }
    ,
    Tr.prototype.genVendorDetails = function(e) {
        Sr.toggleAccordionStatus(e)
    }
    ,
    Tr.prototype.confirmPC = function(e) {
        var t = Qt.isAlertBoxClosedAndValid();
        Nt.NoBanner && Nt.ShowPreferenceCenterCloseButton && !t && Ir.bannerCloseButtonHandler();
        var o = Mt.isBannerVisible();
        !It.moduleInitializer.MobileSDK || !t && o || Sr.closePreferenceCenter(e)
    }
    ,
    Tr.prototype.captureInitialConsent = function() {
        Ht.initialGroupsConsent = JSON.parse(JSON.stringify(Ht.groupsConsent)),
        Ht.initialHostConsent = JSON.parse(JSON.stringify(Ht.hostsConsent)),
        Ht.showGeneralVendors && (Ht.initialGenVendorsConsent = JSON.parse(JSON.stringify(Ht.genVendorsConsent))),
        Nt.IsIabEnabled && (Ht.initialOneTrustIABConsent = JSON.parse(JSON.stringify(Ht.oneTrustIABConsent)),
        Ht.initialVendors = JSON.parse(JSON.stringify(Ht.vendors)),
        Ht.initialVendors.vendorTemplate = Ht.vendors.vendorTemplate),
        Nt.UseGoogleVendors && (Ht.initialAddtlVendorsList = JSON.parse(JSON.stringify(Ht.addtlVendorsList)),
        Ht.initialAddtlVendors = JSON.parse(JSON.stringify(Ht.addtlVendors))),
        Ht.vsIsActiveAndOptOut && (Ht.initialVendorsServiceConsent = new Map(Ht.vsConsent))
    }
    ,
    Tr);
    function Tr() {
        var t = this;
        this.fltgBtnSltr = "#ot-sdk-btn-floating",
        this.fltgBtnFrontBtn = ".ot-floating-button__front button",
        this.fltgBtnBackBtn = ".ot-floating-button__back button",
        this.fltgBtnFSltr = ".ot-floating-button__front svg",
        this.fltgBtnBSltr = ".ot-floating-button__back svg",
        this.pc = null,
        this.allowVisible = !1,
        this.pcLinkSource = null,
        this.isCookieList = !1,
        this.otGuardLogoResolve = null,
        this.otGuardLogoPromise = new Promise(function(e) {
            t.otGuardLogoResolve = e
        }
        ),
        this.showCookieSettingsHandler = function(i) {
            return c(t, void 0, void 0, function() {
                var t, o, n, r;
                return C(this, function(e) {
                    switch (e.label) {
                    case 0:
                        return i && i.stopPropagation(),
                        i && i.target && (t = i.target.className,
                        o = "onetrust-pc-btn-handler" === i.target.id,
                        n = "ot-sdk-show-settings" === t,
                        (o || n) && (r = o ? Ro : qo,
                        Vo.triggerGoogleAnalyticsEvent(Go, r)),
                        Ht.pcSource = i.target),
                        [4, Sr.toggleInfoDisplay()];
                    case 1:
                        return e.sent(),
                        [2, !1]
                    }
                })
            })
        }
        ,
        this.cookiesSettingsBoundListener = this.showCookieSettingsHandler.bind(this),
        this.backBtnHandler = function() {
            return Ht.showVendorService && mr.hideVendorList(),
            Ir.hideVendorsList(),
            Ot.pcName === nt && (qt("#onetrust-pc-sdk " + Kt.P_Content).removeClass("ot-hide"),
            qt("#onetrust-pc-sdk").el[0].removeAttribute("style"),
            t.setPcListContainerHeight()),
            qt("#onetrust-pc-sdk #filter-count").text("0"),
            qt("#onetrust-pc-sdk #vendor-search-handler").length && (qt("#onetrust-pc-sdk #vendor-search-handler").el[0].value = ""),
            Ht.currentGlobalFilteredList = [],
            Ht.filterByCategories = [],
            Ht.filterByIABCategories = [],
            Ht.vendors.searchParam = "",
            Sr.closeFilter(),
            Ht.pcLayer = _.PrefCenterHome,
            t.pcLinkSource ? (t.pcLinkSource.focus(),
            t.pcLinkSource = null) : mn.setPCFocus(mn.getPCElements()),
            !1
        }
        ,
        this.bannerCloseBoundListener = this.bannerCloseButtonHandler.bind(this),
        this.toggleGroupORVendorHandler = function(e) {
            var t = e.currentTarget
              , o = t.dataset.otVsId;
            o ? Sr.toggleVendorServiceHandler.bind(this)(e) : (o = t.dataset.optanongroupid) && Sr.toggleV2Category.bind(this)()
        }
        ,
        this.toggleVendorFromListHandler = function(e) {
            var t = e.currentTarget
              , o = t.checked
              , n = t.dataset.otVsId
              , r = t.dataset.optanongroupid
              , i = document.getElementById("ot-vendor-id-" + n);
            ur.toggleVendorService(r, n, o, i)
        }
        ,
        this.toggleVendorServiceHandler = function(e) {
            var t = e.currentTarget
              , o = t.checked
              , n = t.dataset.otVsId
              , r = t.dataset.optanongroupid;
            ur.toggleVendorService(r, n, o, t);
            var i = Xt.getVSById(n);
            Sr.setAriaLabelforButtonInFilter(i.ServiceName)
        }
        ,
        this.toggleV2Category = function(e, t, o, n) {
            if (!t) {
                var r = this.getAttribute("data-optanongroupid")
                  , i = "function" == typeof this.getAttribute
                  , s = Bt.findIndex(Ht.dataGroupState, function(e) {
                    return i && e.CustomGroupId === r
                });
                t = Ht.dataGroupState[s]
            }
            var a;
            if (void 0 === o && (o = qt(this).is(":checked")),
            Nt.ChoicesBanner && Bt.setCheckedAttribute("#ot-bnr-grp-id-" + t.CustomGroupId, null, o),
            n)
                document.querySelector("#ot-group-id-" + n) && (Bt.setCheckedAttribute("#ot-group-id-" + n, null, o),
                a = document.querySelector("#ot-group-id-" + n));
            else {
                a = this,
                Bt.setCheckedAttribute(null, this, o);
                var l = a.parentElement.querySelector(".ot-switch-nob");
                It.fp.CookieV2VendorServiceScript ? Nt.PCCategoryStyle === se.Toggle && l && l.setAttribute("aria-checked", o) : Nt.PCTemplateUpgrade && l && l.setAttribute("aria-checked", o)
            }
            Nt.PCShowConsentLabels && (a.parentElement.parentElement.querySelector(".ot-label-status").innerHTML = o ? Nt.PCActiveText : Nt.PCInactiveText);
            var c = this instanceof HTMLElement && -1 !== this.getAttribute("id").indexOf("-leg-out");
            Sr.setAriaLabelforButtonInFilter(t.GroupName),
            Sr.updateGroupToggles(t, o, c)
        }
        ,
        this.toggleBannerCategory = function() {
            var t = this
              , e = Bt.findIndex(Ht.dataGroupState, function(e) {
                return "function" == typeof t.getAttribute && e.CustomGroupId === t.getAttribute("data-optanongroupid")
            })
              , o = Ht.dataGroupState[e]
              , n = qt(t).is(":checked");
            Sr.toggleV2Category(null, o, n, o.CustomGroupId)
        }
        ,
        this.toggleSubCategory = function(e, t, o, n) {
            t = t || this.getAttribute("data-optanongroupid");
            var r, i = Xt.getGroupById(t);
            void 0 === o && (o = qt(this).is(":checked")),
            n ? (Bt.setCheckedAttribute("#ot-sub-group-id-" + n, null, o),
            r = document.querySelector("#ot-sub-group-id-" + n)) : (r = this,
            Bt.setCheckedAttribute(null, this, o)),
            Nt.PCShowConsentLabels && (r.parentElement.parentElement.querySelector(".ot-label-status").innerHTML = o ? Nt.PCActiveText : Nt.PCInactiveText);
            var s = this instanceof HTMLElement && -1 !== this.getAttribute("id").indexOf("-leg-out");
            Sr.setAriaLabelforButtonInFilter(i.GroupName),
            Sr.updateSubGroupToggles(i, o, s)
        }
    }
    var Ir, Lr = (_r.prototype.updateDataSubjectTimestamp = function() {
        var e = Qt.alertBoxCloseDate()
          , t = e && Mt.getUTCFormattedDate(e);
        qt(".ot-userid-timestamp").html(Nt.PCenterUserIdTimestampTitleText + ": " + t)
    }
    ,
    _r.prototype.closeBanner = function(e) {
        this.closeOptanonAlertBox(),
        e ? this.allowAll(!1) : this.close(!1)
    }
    ,
    _r.prototype.allowAll = function(e, t) {
        void 0 === t && (t = !1),
        It.moduleInitializer.MobileSDK ? window.OneTrust.AllowAll() : this.AllowAllV2(e, t)
    }
    ,
    _r.prototype.bannerActionsHandler = function(t, n) {
        mo.setLandingPathParam(Ve),
        Ht.groupsConsent = [],
        Ht.hostsConsent = [],
        Ht.genVendorsConsent = {};
        var r = {};
        Nt.Groups.forEach(function(e) {
            if (e.IsAboutGroup)
                return !1;
            y(e.SubGroups, [e]).forEach(function(e) {
                var o = !!t || !!n && Xt.isAlwaysActiveGroup(e);
                -1 < Pt.indexOf(e.Type) && Ht.groupsConsent.push(e.CustomGroupId + ":" + (o && e.HasConsentOptOut ? "1" : "0")),
                e.Hosts.length && Mt.isOptOutEnabled() && e.Hosts.forEach(function(e) {
                    if (r[e.HostId])
                        fo.updateHostStatus(e, o);
                    else {
                        r[e.HostId] = !0;
                        var t = fo.isHostPartOfAlwaysActiveGroup(e.HostId) || o;
                        Ht.hostsConsent.push(e.HostId + ":" + (t ? "1" : "0"))
                    }
                }),
                Ht.genVenOptOutEnabled && e.GeneralVendorsIds && e.GeneralVendorsIds.length && e.GeneralVendorsIds.forEach(function(e) {
                    go.updateGenVendorStatus(e, o)
                })
            })
        }),
        Nt.IsIabEnabled && (t ? this.iab.allowAllhandler() : this.iab.rejectAllHandler()),
        Rn.hideConsentNoticeV2(),
        so.writeGrpParam(Ee.OPTANON_CONSENT),
        so.writeHstParam(Ee.OPTANON_CONSENT),
        Ht.genVenOptOutEnabled && so.writeGenVenCookieParam(Ee.OPTANON_CONSENT),
        Ht.vsIsActiveAndOptOut && so.writeVSConsentCookieParam(Ee.OPTANON_CONSENT),
        En.substitutePlainTextScriptTags(),
        Dn.updateGtmMacros(),
        this.executeOptanonWrapper()
    }
    ,
    _r.prototype.nextPageCloseBanner = function() {
        mo.isLandingPage() || Qt.isAlertBoxClosedAndValid() || this.closeBanner(Nt.NextPageAcceptAllCookies)
    }
    ,
    _r.prototype.rmScrollAndClickBodyEvents = function() {
        Nt.ScrollCloseBanner && window.removeEventListener("scroll", this.scrollCloseBanner),
        Nt.OnClickCloseBanner && document.body.removeEventListener("click", this.bodyClickEvent)
    }
    ,
    _r.prototype.onClickCloseBanner = function(e) {
        Qt.isAlertBoxClosedAndValid() || (Vo.triggerGoogleAnalyticsEvent(Go, Oo),
        this.closeBanner(Nt.OnClickAcceptAllCookies),
        e.stopPropagation()),
        Ir.rmScrollAndClickBodyEvents()
    }
    ,
    _r.prototype.scrollCloseBanner = function() {
        var e = qt(document).height() - qt(window).height();
        0 === e && (e = qt(window).height());
        var t = 100 * qt(window).scrollTop() / e;
        t <= 0 && (t = 100 * (document.scrollingElement && document.scrollingElement.scrollTop || document.documentElement && document.documentElement.scrollTop || document.body && document.body.scrollTop) / (document.scrollingElement && document.scrollingElement.scrollHeight || document.documentElement && document.documentElement.scrollHeight || document.body && document.body.scrollHeight)),
        25 < t && !Qt.isAlertBoxClosedAndValid() && (!Ht.isPCVisible || Nt.NoBanner) ? (Vo.triggerGoogleAnalyticsEvent(Go, Oo),
        Ir.closeBanner(Nt.ScrollAcceptAllCookies),
        Ir.rmScrollAndClickBodyEvents()) : Qt.isAlertBoxClosedAndValid() && Ir.rmScrollAndClickBodyEvents()
    }
    ,
    _r.prototype.AllowAllV2 = function(e, t) {
        void 0 === t && (t = !1);
        for (var o = this.groupsClass.getAllGroupElements(), n = 0; n < o.length; n++) {
            var r = Xt.getGroupById(o[n].getAttribute("data-optanongroupid"));
            this.groupsClass.toggleGrpElements(o[n], r, !0),
            this.groupsClass.toogleSubGroupElement(o[n], !0, !1, !0),
            this.groupsClass.toogleSubGroupElement(o[n], !0, !0, !0)
        }
        Ht.showVendorService && ur.consentAll(!0),
        this.bannerActionsHandler(!0, !1),
        this.consentTransactions(e, !0, t),
        Nt.IsIabEnabled && (this.iab.updateIabVariableReference(),
        this.iab.updateVendorsDOMToggleStatus(!0),
        this.updateVendorLegBtns(!0))
    }
    ,
    _r.prototype.rejectAll = function(e, t) {
        void 0 === t && (t = !1);
        for (var o = t ? U[5] : U[2], n = this.groupsClass.getAllGroupElements(), r = 0; r < n.length; r++) {
            var i = Xt.getGroupById(n[r].getAttribute("data-optanongroupid"));
            "always active" !== Xt.getGrpStatus(i).toLowerCase() && (Sn.toggleGrpElements(n[r], i, !1),
            this.groupsClass.toogleSubGroupElement(n[r], !1, !1, !0),
            this.groupsClass.toogleSubGroupElement(n[r], !1, !0, !0))
        }
        Ht.showVendorService && ur.consentAll(!1),
        this.bannerActionsHandler(!1, !0),
        o !== Ht.consentInteractionType && this.consentTransactions(e, !1, t),
        Nt.IsIabEnabled && (this.iab.updateIabVariableReference(),
        this.iab.updateVendorsDOMToggleStatus(!1),
        this.updateVendorLegBtns(!1))
    }
    ,
    _r.prototype.executeCustomScript = function() {
        Nt.CustomJs && new Function(Nt.CustomJs)()
    }
    ,
    _r.prototype.updateConsentData = function(e) {
        mo.setLandingPathParam(Ve),
        Nt.IsIabEnabled && !e && this.iab.saveVendorStatus(),
        so.writeGrpParam(Ee.OPTANON_CONSENT),
        so.writeHstParam(Ee.OPTANON_CONSENT),
        Ht.showGeneralVendors && Nt.GenVenOptOut && so.writeGenVenCookieParam(Ee.OPTANON_CONSENT),
        Ht.vsIsActiveAndOptOut && so.writeVSConsentCookieParam(Ee.OPTANON_CONSENT),
        En.substitutePlainTextScriptTags(),
        Dn.updateGtmMacros()
    }
    ,
    _r.prototype.close = function(e, t) {
        if (void 0 === t && (t = m.Banner),
        Rn.hideConsentNoticeV2(),
        this.updateConsentData(e),
        Nt.IsConsentLoggingEnabled) {
            var o = t === m.PC ? Wn : t === m.Banner ? jn : Ot.apiSource
              , n = t === m.PC ? Mn : t === m.Banner ? qn : Un;
            Ht.bannerCloseSource === f.ContinueWithoutAcceptingButton && (o = Yn),
            Ht.bannerCloseSource === f.BannerSaveSettings && (o = Jn),
            eo.createConsentTxn(!1, n + " - " + o, t === m.PC)
        } else
            Qt.dispatchConsentEvent();
        this.executeOptanonWrapper()
    }
    ,
    _r.prototype.executeOptanonWrapper = function() {
        try {
            if (this.executeCustomScript(),
            "function" == typeof window.OptanonWrapper && "undefined" !== window.OptanonWrapper) {
                window.OptanonWrapper();
                for (var e = 0, t = Ht.srcExecGrpsTemp; e < t.length; e++) {
                    var o = t[e];
                    -1 === Ht.srcExecGrps.indexOf(o) && Ht.srcExecGrps.push(o)
                }
                Ht.srcExecGrpsTemp = [];
                for (var n = 0, r = Ht.htmlExecGrpsTemp; n < r.length; n++)
                    o = r[n],
                    -1 === Ht.htmlExecGrps.indexOf(o) && Ht.htmlExecGrps.push(o);
                Ht.htmlExecGrpsTemp = []
            }
        } catch (e) {
            console.warn("Error in Optanon wrapper, please review your code. " + e)
        }
    }
    ,
    _r.prototype.updateVendorLegBtns = function(e) {
        if (Ot.legIntSettings.PAllowLI && Ot.legIntSettings.PShowLegIntBtn)
            for (var t = qt(Kt.P_Vendor_Container + " .ot-leg-btn-container").el, o = 0; o < t.length; o++)
                this.groupsClass.updateLegIntBtnElement(t[o], e)
    }
    ,
    _r.prototype.showFltgCkStgButton = function() {
        var e = qt("#ot-sdk-btn-floating");
        e.removeClass("ot-hide"),
        e.removeClass("ot-pc-open"),
        Nt.cookiePersistentLogo.includes("ot_guard_logo.svg") && qt(".ot-floating-button__front svg").attr("aria-hidden", ""),
        qt(".ot-floating-button__back svg").attr("aria-hidden", "true")
    }
    ,
    _r.prototype.consentTransactions = function(e, t, o) {
        void 0 === o && (o = !1),
        eo && !e && Nt.IsConsentLoggingEnabled ? eo.createConsentTxn(!1, (o ? Mn : qn) + " - " + (t ? zn : Kn), o) : Qt.dispatchConsentEvent()
    }
    ,
    _r.prototype.hideVendorsList = function() {
        Rn.checkIfPcSdkContainerExist() || (Nt.PCTemplateUpgrade ? qt("#onetrust-pc-sdk " + Kt.P_Content).removeClass("ot-hide") : qt("#onetrust-pc-sdk .ot-main-content").show(),
        qt("#onetrust-pc-sdk #close-pc-btn-handler.main").show(),
        qt("#onetrust-pc-sdk " + Kt.P_Vendor_List).addClass("ot-hide"))
    }
    ,
    _r.prototype.resetConsent = function() {
        var e = this;
        Ht.groupsConsent = JSON.parse(JSON.stringify(Ht.initialGroupsConsent)),
        Ht.hostsConsent = JSON.parse(JSON.stringify(Ht.initialHostConsent)),
        Ht.showGeneralVendors && (Ht.genVendorsConsent = JSON.parse(JSON.stringify(Ht.initialGenVendorsConsent))),
        Ht.vsIsActiveAndOptOut && (Ht.vsConsent = new Map(Ht.initialVendorsServiceConsent)),
        Nt.IsIabEnabled && (Ht.oneTrustIABConsent = JSON.parse(JSON.stringify(Ht.initialOneTrustIABConsent)),
        Ht.vendors = JSON.parse(JSON.stringify(Ht.initialVendors)),
        Ht.vendors.vendorTemplate = Ht.initialVendors.vendorTemplate),
        Nt.UseGoogleVendors && (Ht.addtlVendors = JSON.parse(JSON.stringify(Ht.initialAddtlVendors)),
        Ht.addtlVendorsList = JSON.parse(JSON.stringify(Ht.initialAddtlVendorsList))),
        this.updateConsentData(!1),
        setTimeout(function() {
            e.resetConsentUI()
        }, 400)
    }
    ,
    _r.prototype.resetConsentUI = function() {
        Sn.getAllGroupElements().forEach(function(e) {
            var t = e.getAttribute("data-optanongroupid")
              , o = Xt.getGroupById(t)
              , n = Ir.isGroupActive(o, t);
            Ot.pcName === st && Nt.PCTemplateUpgrade && (e = document.querySelector("#ot-desc-id-" + e.getAttribute("data-optanongroupid")));
            var r = e.querySelector(".ot-label-status");
            if (Nt.PCShowConsentLabels && r && (r.innerHTML = n ? Nt.PCActiveText : Nt.PCInactiveText),
            o.Type === gt || o.Type === mt) {
                var i = Mt.isBundleOrStackActive(o, Ht.initialGroupsConsent)
                  , s = e.querySelector('input[class*="category-switch-handler"]');
                Bt.setCheckedAttribute(null, s, i);
                for (var a = e.querySelectorAll("li" + Kt.P_Subgrp_li), l = 0; l < a.length; l++) {
                    var c = Xt.getGroupById(a[l].getAttribute("data-optanongroupid"))
                      , d = c.OptanonGroupId
                      , u = Ir.isGroupActive(c, d)
                      , p = a[l].querySelector('input[class*="cookie-subgroup-handler"]')
                      , h = a[l].querySelector(".ot-label-status");
                    Nt.PCShowConsentLabels && h && (r.innerHTML = u ? Nt.PCActiveText : Nt.PCInactiveText),
                    Bt.setCheckedAttribute(null, p, u),
                    Ir.resetLegIntButton(c, a[l])
                }
            } else
                s = e.querySelector('input[class*="category-switch-handler"]'),
                Bt.setCheckedAttribute(null, s, n),
                Ir.resetLegIntButton(o, e)
        }),
        Nt.IsIabEnabled && tr.toggleVendorConsent();
        var e = qt("#onetrust-pc-sdk .ot-gnven-chkbox-handler").el;
        if (Ht.showGeneralVendors && e && e.length) {
            for (var t = 0, o = e; t < o.length; t++) {
                var n = (l = o[t]).getAttribute("gn-vid")
                  , r = Boolean(Ht.genVendorsConsent[n]);
                Bt.setCheckedAttribute("", l, r),
                go.updateGenVendorStatus(n, r)
            }
            Gn.genVenSelectAllTglEvent()
        }
        var i = qt("#onetrust-pc-sdk .ot-addtlven-chkbox-handler").el;
        if (Nt.UseGoogleVendors && i && i.length)
            for (var s = 0, a = i; s < a.length; s++) {
                var l;
                n = (l = a[s]).getAttribute("addtl-vid"),
                Ht.addtlVendorsList[n] && (r = Boolean(Ht.addtlVendors.vendorSelected[n]),
                Bt.setCheckedAttribute("", l, r))
            }
        Ht.vsIsActiveAndOptOut && ur.resetVendorUIState(Ht.vsConsent)
    }
    ,
    _r.prototype.isGroupActive = function(e, t) {
        var o;
        if (e.IabGrpId) {
            var n = void 0;
            n = e.Type === vt ? Ht.initialVendors.selectedSpecialFeatures : e.IsLegIntToggle ? Ht.initialVendors.selectedLegInt : Ht.initialVendors.selectedPurpose,
            o = -1 !== Ft.inArray(e.IabGrpId + ":true", n)
        } else
            o = -1 !== Ft.inArray(t + ":1", Ht.initialGroupsConsent);
        return o
    }
    ,
    _r.prototype.resetLegIntButton = function(e, t) {
        if (Ot.legIntSettings.PAllowLI && e.Type === ft && e.HasLegIntOptOut && Ot.legIntSettings.PShowLegIntBtn) {
            var o = !0;
            -1 < Ht.vendors.selectedLegInt.indexOf(e.IabGrpId + ":false") && (o = !1),
            Sn.updateLegIntBtnElement(t, o)
        }
    }
    ,
    _r.prototype.handleTogglesOnSingularConsentUpdate = function(e, t, o) {
        if (this.closeOptanonAlertBox(),
        e === dt)
            for (var n = Xt.getGroupById(t), r = this.groupsClass.getAllGroupElements(), i = 0; i < r.length; i++) {
                var s = Xt.getGroupById(r[i].getAttribute("data-optanongroupid"));
                if (s.OptanonGroupId === n.OptanonGroupId && !s.Parent) {
                    Sr.toggleV2Category(null, s, o, s.CustomGroupId);
                    break
                }
                var a = s.SubGroups.find(function(e) {
                    return e.OptanonGroupId === n.OptanonGroupId
                });
                a && Sr.toggleSubCategory(null, a.CustomGroupId, o, a.CustomGroupId)
            }
        else if (e === ht) {
            var l = Xt.getGrpByVendorId(t);
            l && ur.toggleVendorService(l.CustomGroupId, t, o)
        }
        this.close(!1, m.API)
    }
    ,
    _r);
    function _r() {
        var o = this;
        this.iab = Gn,
        this.groupsClass = Sn,
        this.closeOptanonAlertBox = function() {
            if (Mt.hideBanner(),
            Nt.NtfyConfig.ShowNtfy && $n.hideSyncNtfy(),
            Ot.isOptInMode || !Ot.isOptInMode && !Qt.isAlertBoxClosedAndValid())
                Vo.setAlertBoxClosed(!0),
                Nt.PCTemplateUpgrade && Nt.PCenterUserIdTitleText && Nt.IsConsentLoggingEnabled && o.updateDataSubjectTimestamp();
            else if (Qt.isAlertBoxClosedAndValid()) {
                var e = qt(".onetrust-pc-dark-filter").el[0];
                e && "none" !== getComputedStyle(e).getPropertyValue("display") && qt(".onetrust-pc-dark-filter").fadeOut(400)
            }
            hn.csBtnGroup && o.showFltgCkStgButton()
        }
        ,
        this.bodyClickEvent = function(e) {
            var t = e.target;
            t.closest("#onetrust-banner-sdk") || t.closest("#onetrust-pc-sdk") || t.closest(".onetrust-pc-dark-filter") || t.closest(".ot-sdk-show-settings") || t.closest(".optanon-show-settings") || t.closest(".optanon-toggle-display") || Ir.onClickCloseBanner(e)
        }
        ,
        this.bannerCloseButtonHandler = function(e) {
            if (void 0 === e && (e = !1),
            Ir.closeOptanonAlertBox(),
            It.moduleInitializer.MobileSDK)
                window.OneTrust.Close();
            else {
                var t = Ht.bannerCloseSource === f.ConfirmChoiceButton ? m.PC : m.Banner;
                Ir.close(e, t)
            }
            return !1
        }
        ,
        this.allowAllEventHandler = function(e) {
            void 0 === e && (e = !1);
            var t = e ? "Preferences Allow All" : "Banner Accept Cookies";
            Vo.triggerGoogleAnalyticsEvent(Go, t),
            o.allowAllEvent(!1, e),
            o.hideVendorsList()
        }
        ,
        this.allowAllEvent = function(e, t) {
            void 0 === e && (e = !1),
            void 0 === t && (t = !1),
            o.closeOptanonAlertBox(),
            Ir.allowAll(e, t)
        }
        ,
        this.rejectAllEventHandler = function(e) {
            void 0 === e && (e = !1);
            var t = e ? "Preferences Reject All" : "Banner Reject All";
            Vo.triggerGoogleAnalyticsEvent(Go, t),
            It.moduleInitializer.MobileSDK ? window.OneTrust.RejectAll() : (o.rejectAllEvent(!1, e),
            o.hideVendorsList())
        }
        ,
        this.rejectAllEvent = function(e, t) {
            void 0 === e && (e = !1),
            void 0 === t && (t = !1),
            o.closeOptanonAlertBox(),
            Qt.isIABCrossConsentEnabled() ? Ot.thirdPartyiFrameLoaded ? o.rejectAll(e, t) : Ot.thirdPartyiFramePromise.then(function() {
                o.rejectAll(e, t)
            }) : o.rejectAll(e, t)
        }
    }
    var Vr, Br = (Er.prototype.initBanner = function() {
        this.canImpliedConsentLandingPage(),
        It.moduleInitializer.CookieSPAEnabled ? qt(window).on("otloadbanner", this.windowLoadBanner.bind(this)) : qt(window).one("otloadbanner", this.windowLoadBanner.bind(this))
    }
    ,
    Er.prototype.insertCSBtnHtmlAndCss = function(e) {
        document.getElementById("onetrust-style").innerHTML += hn.csBtnGroup.css;
        var t = document.createElement("div");
        qt(t).html(hn.csBtnGroup.html);
        var o = t.querySelector("#ot-sdk-btn-floating");
        e && o && qt(o).removeClass("ot-hide"),
        qt("#onetrust-consent-sdk").append(o),
        Nt.cookiePersistentLogo && (Nt.cookiePersistentLogo.includes("ot_guard_logo.svg") ? this.applyPersistentSvgOnDOM() : qt(".ot-floating-button__front, .ot-floating-button__back").addClass("custom-persistent-icon"))
    }
    ,
    Er.prototype.applyPersistentSvgOnDOM = function() {
        return c(this, void 0, void 0, function() {
            var t;
            return C(this, function(e) {
                switch (e.label) {
                case 0:
                    return [4, dn.getPersistentCookieSvg()];
                case 1:
                    return t = e.sent(),
                    qt(this.FLOATING_COOKIE_FRONT_BTN).html(t),
                    Sr.otGuardLogoResolve(!0),
                    [2]
                }
            })
        })
    }
    ,
    Er.prototype.canImpliedConsentLandingPage = function() {
        this.isImpliedConsent() && !mo.isLandingPage() && "true" === Vt.readCookieParam(Ee.OPTANON_CONSENT, Ae) && this.checkForRefreshCloseImplied()
    }
    ,
    Er.prototype.isImpliedConsent = function() {
        return Nt.ConsentModel && "implied consent" === Nt.ConsentModel.Name.toLowerCase()
    }
    ,
    Er.prototype.checkForRefreshCloseImplied = function() {
        Ir.closeOptanonAlertBox(),
        Ir.close(!0)
    }
    ,
    Er.prototype.hideCustomHtml = function() {
        var e = document.getElementById("onetrust-banner-sdk");
        e && Lt(e, "display: none;")
    }
    ,
    Er.prototype.windowLoadBanner = function() {
        return c(this, void 0, void 0, function() {
            var t, o, n, r, i, s, a, l, c, d;
            return C(this, function(e) {
                switch (e.label) {
                case 0:
                    return this.core.substitutePlainTextScriptTags(),
                    t = It.moduleInitializer,
                    qt("#onetrust-consent-sdk").length ? n = document.getElementById("onetrust-consent-sdk") : (n = document.createElement("div"),
                    qt(n).attr("id", "onetrust-consent-sdk"),
                    qt(document.body).append(n)),
                    qt(".onetrust-pc-dark-filter").length || (o = document.createElement("div"),
                    qt(o).attr("class", "onetrust-pc-dark-filter"),
                    qt(o).attr("class", "ot-hide"),
                    qt(o).attr("class", "ot-fade-in"),
                    n.firstChild ? n.insertBefore(o, n.firstChild) : qt(n).append(o)),
                    Nt.IsIabEnabled && this.iab.updateIabVariableReference(),
                    r = Qt.isAlertBoxClosedAndValid(),
                    i = Nt.ShowAlertNotice && !r && !Nt.NoBanner && !Ht.hideBanner,
                    s = Nt.ShowAlertNotice && !r && Nt.NoBanner,
                    Ht.ntfyRequired ? (this.hideCustomHtml(),
                    $n.init(),
                    $n.changeState()) : i ? Sr.initializeAlartHtmlAndHandler() : this.hideCustomHtml(),
                    t.IsSuppressPC || (gr.insertPcHtml(),
                    Sr.initialiseConsentNoticeHandlers(),
                    Nt.IsIabEnabled && this.iab.InitializeVendorList()),
                    t.RemoteActionsEnabled && ((a = document.getElementById("hbbtv")) && a.remove(),
                    (l = document.createElement("script")).id = "hbbtv",
                    l.src = Ht.storageBaseURL + "/scripttemplates/" + It.moduleInitializer.Version + "/hbbtv.js",
                    l.type = "text/javascript",
                    qt(document.body).append(l)),
                    this.insertCSBtn(!i),
                    s ? [4, Sr.toggleInfoDisplay()] : [3, 2];
                case 1:
                    e.sent(),
                    e.label = 2;
                case 2:
                    return Sr.insertCookieSettingText(),
                    c = qt(this.FLOATING_COOKIE_BTN),
                    d = qt(this.FLOATING_COOKIE_FRONT_BTN),
                    c.length && (c.attr("title", Nt.CookieSettingButtonText),
                    d.el[0].setAttribute("aria-label", Nt.AriaOpenPreferences)),
                    In.insertCookiePolicyHtml(),
                    Ir.executeOptanonWrapper(),
                    Vt.readCookieParam(Ee.OPTANON_CONSENT, ao) || so.writeGrpParam(Ee.OPTANON_CONSENT),
                    Vt.readCookieParam(Ee.OPTANON_CONSENT, lo) || so.writeHstParam(Ee.OPTANON_CONSENT),
                    Ht.showGeneralVendors && !Vt.readCookieParam(Ee.OPTANON_CONSENT, co) && so.writeGenVenCookieParam(Ee.OPTANON_CONSENT),
                    Ht.vsIsActiveAndOptOut && !Vt.readCookieParam(Ee.OPTANON_CONSENT, uo) && so.writeVSConsentCookieParam(Ee.OPTANON_CONSENT),
                    i && mn.setBannerFocus(),
                    [2]
                }
            })
        })
    }
    ,
    Er.prototype.insertCSBtn = function(e) {
        hn.csBtnGroup && (this.insertCSBtnHtmlAndCss(e),
        Sr.initFlgtCkStgBtnEventHandlers())
    }
    ,
    Er);
    function Er() {
        this.iab = Gn,
        this.core = En,
        this.FLOATING_COOKIE_BTN = "#ot-sdk-btn-floating",
        this.FLOATING_COOKIE_FRONT_BTN = "#ot-sdk-btn-floating .ot-floating-button__front .ot-floating-button__open"
    }
    var wr, xr = (Gr.prototype.initialiseLandingPath = function() {
        var e = Qt.needReconsent();
        if (mo.isLandingPage())
            mo.setLandingPathParam(location.href);
        else {
            if (e && !Qt.awaitingReconsent())
                return mo.setLandingPathParam(location.href),
                void Vt.writeCookieParam(Ee.OPTANON_CONSENT, Ae, !0);
            e || Vt.writeCookieParam(Ee.OPTANON_CONSENT, Ae, !1),
            mo.setLandingPathParam(Ve),
            Ot.isSoftOptInMode && !It.moduleInitializer.MobileSDK && Vo.setAlertBoxClosed(!0),
            Nt.NextPageCloseBanner && Nt.ShowAlertNotice && Ir.nextPageCloseBanner()
        }
    }
    ,
    Gr);
    function Gr() {}
    var Or, Nr = (Dr.prototype.IsAlertBoxClosedAndValid = function() {
        return Qt.isAlertBoxClosedAndValid()
    }
    ,
    Dr.prototype.LoadBanner = function() {
        Vo.loadBanner()
    }
    ,
    Dr.prototype.Init = function(e) {
        void 0 === e && (e = !1),
        Se.insertViewPortTag(),
        hn.ensureHtmlGroupDataInitialised(),
        Dn.updateGtmMacros(!1),
        wr.initialiseLandingPath(),
        e || ar.initialiseCssReferences()
    }
    ,
    Dr.prototype.FetchAndDownloadPC = function() {
        Sr.fetchAndSetupPC()
    }
    ,
    Dr.prototype.ToggleInfoDisplay = function() {
        Vo.triggerGoogleAnalyticsEvent(Go, Mo),
        Sr.toggleInfoDisplay()
    }
    ,
    Dr.prototype.Close = function(e) {
        Sr.close(e)
    }
    ,
    Dr.prototype.AllowAll = function(e) {
        Ir.allowAllEvent(e)
    }
    ,
    Dr.prototype.RejectAll = function(e) {
        Ir.rejectAllEvent(e)
    }
    ,
    Dr.prototype.setDataSubjectIdV2 = function(e, t) {
        void 0 === t && (t = !1),
        e && e.trim() && (e = e.replace(/ /g, ""),
        Vt.writeCookieParam(Ee.OPTANON_CONSENT, Te, e, !0),
        Ht.dsParams.isAnonymous = t)
    }
    ,
    Dr.prototype.getDataSubjectId = function() {
        return Vt.readCookieParam(Ee.OPTANON_CONSENT, Te, !0)
    }
    ,
    Dr.prototype.synchroniseCookieWithPayload = function(i) {
        var e = Vt.readCookieParam(Ee.OPTANON_CONSENT, "groups")
          , t = Bt.strToArr(e)
          , s = [];
        t.forEach(function(e) {
            var t = e.split(":")
              , o = Xt.getGroupById(t[0])
              , n = Bt.findIndex(i, function(e) {
                return e.Id === o.PurposeId
            })
              , r = i[n];
            r ? r.TransactionType === we ? (s.push(t[0] + ":1"),
            o.Parent ? Sr.toggleSubCategory(null, o.CustomGroupId, !0, o.CustomGroupId) : Sr.toggleV2Category(null, o, !0, o.CustomGroupId)) : (s.push(t[0] + ":0"),
            o.Parent ? Sr.toggleSubCategory(null, o.CustomGroupId, !1, o.CustomGroupId) : Sr.toggleV2Category(null, o, !1, o.CustomGroupId)) : s.push(t[0] + ":" + t[1])
        }),
        so.writeGrpParam(Ee.OPTANON_CONSENT, s)
    }
    ,
    Dr.prototype.getGeolocationData = function() {
        return Ht.userLocation
    }
    ,
    Dr.prototype.TriggerGoogleAnalyticsEvent = function(e, t, o, n) {
        Vo.triggerGoogleAnalyticsEvent(e, t, o, n)
    }
    ,
    Dr.prototype.ReconsentGroups = function() {
        var r = !1
          , e = Vt.readCookieParam(Ee.OPTANON_CONSENT, "groups")
          , i = Bt.strToArr(e)
          , s = Bt.strToArr(e.replace(/:0|:1/g, ""))
          , a = !1
          , t = Vt.readCookieParam(Ee.OPTANON_CONSENT, "hosts")
          , l = Bt.strToArr(t)
          , c = Bt.strToArr(t.replace(/:0|:1/g, ""))
          , d = ["inactive", "inactive landingpage", "do not track"];
        e && (Nt.Groups.forEach(function(e) {
            y(e.SubGroups, [e]).forEach(function(e) {
                var t = e.CustomGroupId
                  , o = Bt.indexOf(s, t);
                if (-1 !== o) {
                    var n = Xt.getGrpStatus(e).toLowerCase();
                    -1 < d.indexOf(n) && (r = !0,
                    i[o] = t + ("inactive landingpage" === n ? ":1" : ":0"))
                }
            })
        }),
        r && so.writeGrpParam(Ee.OPTANON_CONSENT, i)),
        t && (Nt.Groups.forEach(function(e) {
            y(e.SubGroups, [e]).forEach(function(n) {
                n.Hosts.forEach(function(e) {
                    var t = Bt.indexOf(c, e.HostId);
                    if (-1 !== t) {
                        var o = Xt.getGrpStatus(n).toLowerCase();
                        -1 < d.indexOf(o) && (a = !0,
                        l[t] = e.HostId + ("inactive landingpage" === o ? ":1" : ":0"))
                    }
                })
            })
        }),
        a && so.writeHstParam(Ee.OPTANON_CONSENT, l))
    }
    ,
    Dr.prototype.SetAlertBoxClosed = function(e) {
        Vo.setAlertBoxClosed(e)
    }
    ,
    Dr.prototype.GetDomainData = function() {
        return Ot.pubDomainData
    }
    ,
    Dr.prototype.setGeoLocation = function(e, t) {
        void 0 === t && (t = ""),
        Ht.userLocation = {
            country: e,
            state: t
        }
    }
    ,
    Dr.prototype.changeLang = function(t) {
        if (t !== Ht.lang) {
            var o = It.moduleInitializer;
            dn.getLangJson(t).then(function(e) {
                e ? (Ot.init(e),
                hn.fetchAssets(t).then(function() {
                    var e = document.getElementById("onetrust-style");
                    e && (e.textContent = ""),
                    ar.initialiseCssReferences(),
                    o.IsSuppressPC && !Ht.isPCVisible || (Bt.removeChild(qt("#onetrust-pc-sdk").el),
                    Ht.vendorDomInit = !1,
                    Ht.genVendorDomInit = !1,
                    gr.insertPcHtml(),
                    Sr.initialiseConsentNoticeHandlers(),
                    Nt.IsIabEnabled && Gn.InitializeVendorList(),
                    Ht.isPCVisible && Sr.restorePc());
                    var t = !0;
                    Qt.isAlertBoxClosedAndValid() || o.IsSuppressBanner && (!o.IsSuppressBanner || Ht.skipAddingHTML) || Nt.NoBanner || (Bt.removeChild(qt("#onetrust-banner-sdk").el),
                    Sr.initializeAlartHtmlAndHandler(),
                    t = !1),
                    Or.initCookiePolicyAndSettings(),
                    Bt.removeChild(qt("#ot-sdk-btn-floating").el),
                    Vr.insertCSBtn(t),
                    Or.processedHtml = null
                })) : console.error("Language:" + t + " doesn't exist for the geo rule")
            })
        }
    }
    ,
    Dr.prototype.initCookiePolicyAndSettings = function(e) {
        var t, o;
        void 0 === e && (e = !1),
        e && (null !== (t = document.querySelector(".ot-sdk-show-settings")) && void 0 !== t && t.removeEventListener("click", Sr.cookiesSettingsBoundListener),
        null !== (o = document.querySelector(".optanon-toggle-display")) && void 0 !== o && o.removeEventListener("click", Sr.cookiesSettingsBoundListener)),
        In.insertCookiePolicyHtml(),
        Sr.insertCookieSettingText(e)
    }
    ,
    Dr.prototype.showVendorsList = function() {
        Ht.pcLayer !== _.VendorList && (Sr.showAllVendors(),
        Vo.triggerGoogleAnalyticsEvent(Go, jo))
    }
    ,
    Dr.prototype.getTestLogData = function() {
        var e = Nt.Groups
          , t = Ot.pubDomainData
          , o = It.moduleInitializer.Version;
        console.info("%cWelcome to OneTrust Log", "padding: 8px; background-color: #43c233; color: white; font-style: italic; border: 1px solid black; font-size: 1.5em;"),
        console.info("Script is for: %c" + (t.Domain ? t.Domain : Nt.optanonCookieDomain), "padding: 4px 6px; font-style: italic; border: 2px solid #43c233; font-size: 12px;"),
        console.info("Script Version Published: " + o),
        console.info("The consent model is: " + t.ConsentModel.Name);
        var n = null !== Qt.alertBoxCloseDate();
        console.info("Consent has " + (n ? "" : "not ") + "been given " + (n ? "👍" : "🛑"));
        var r = [];
        e.forEach(function(e) {
            var t = "";
            t = e.Status && "always active" === e.Status.toLowerCase() ? "Always Active" : Sn.isGroupActive(e) ? "Active" : "Inactive",
            r.push({
                CustomGroupId: e.CustomGroupId,
                GroupName: e.GroupName,
                Status: t
            })
        }),
        console.groupCollapsed("Current Category Status"),
        console.table(r),
        console.groupEnd();
        var i = [];
        t.GeneralVendors.forEach(function(e) {
            i.push({
                CustomGroupId: e.VendorCustomId,
                Name: e.Name,
                Status: Or.isCategoryActive(e.VendorCustomId) ? "active" : "inactive"
            })
        }),
        console.groupCollapsed("General Vendor Ids"),
        console.table(i),
        console.groupEnd();
        var s = Ot.getRegionRule()
          , a = Ht.userLocation
          , l = It.moduleInitializer.GeoRuleGroupName;
        Ot.conditionalLogicEnabled ? console.groupCollapsed("Geolocation, Template & Condition") : console.groupCollapsed("Geolocation and Template"),
        Ht.userLocation.country && console.info("The Geolocation is " + a.country.toUpperCase()),
        console.info("The Geolocation rule is " + s.Name),
        console.info("The GeolocationRuleGroup is " + l),
        Ot.canUseConditionalLogic ? (console.info("The Condition name is " + Ot.Condition.Name),
        console.info("The TemplateName is " + Ot.Condition.TemplateName)) : console.info("The TemplateName is " + s.TemplateName),
        console.groupEnd();
        var c = e.filter(function(e) {
            return Sn.isGroupActive(e) && "COOKIE" === e.Type
        });
        console.groupCollapsed("The cookies expected to be active if blocking has been implemented are"),
        c.forEach(function(e) {
            console.groupCollapsed(e.GroupName);
            var t = Or.getAllFormatCookiesForAGroup(e);
            console.table(t, ["Name", "Host", "description"]),
            console.groupEnd()
        }),
        console.groupEnd()
    }
    ,
    Dr.prototype.isCategoryActive = function(e) {
        return -1 !== window.OptanonActiveGroups.indexOf(e)
    }
    ,
    Dr.prototype.getAllFormatCookiesForAGroup = function(e) {
        var t, o = [];
        return e.FirstPartyCookies.forEach(function(e) {
            return o.push({
                Name: e.Name,
                Host: e.Host,
                Description: e.description
            })
        }),
        (null === (t = e.Hosts) || void 0 === t ? void 0 : t.reduce(function(e, t) {
            return e.concat(JSON.parse(JSON.stringify(t.Cookies)))
        }, [])).forEach(function(e) {
            return o.push({
                Name: e.Name,
                Host: e.Host,
                Description: e.description
            })
        }),
        o
    }
    ,
    Dr.prototype.updateSingularConsent = function(e, t) {
        Ot.apiSource = P.UpdateConsent;
        var o = t.split(":")[0]
          , n = t.split(":")[1]
          , r = Boolean(Number(n));
        e === dt ? "always active" === Xt.getGrpStatus(Xt.getGroupById(o)) || (Or.updateConsentArray(Ht.groupsConsent, o, n),
        Ir.handleTogglesOnSingularConsentUpdate(e, o, r)) : e === ut ? (Or.updateConsentArray(Ht.hostsConsent, o, n),
        Ir.handleTogglesOnSingularConsentUpdate(e)) : e === pt ? (Ht.genVendorsConsent[o] = r,
        Ir.handleTogglesOnSingularConsentUpdate(e)) : e === ht && Ir.handleTogglesOnSingularConsentUpdate(e, o, r)
    }
    ,
    Dr.prototype.vendorServiceEnabled = function() {
        return Ht.showVendorService
    }
    ,
    Dr.prototype.updateConsentArray = function(e, t, o) {
        var n = e.findIndex(function(e) {
            return e.includes(t + ":0") || e.includes(t + ":1")
        });
        -1 < n ? e[n] = t + ":" + o : e.push(t + ":" + o)
    }
    ,
    Dr);
    function Dr() {
        this.processedHtml = "",
        this.useGeoLocationService = !0,
        this.IsAlertBoxClosed = this.IsAlertBoxClosedAndValid,
        this.InitializeBanner = function() {
            return Vr.initBanner()
        }
        ,
        this.getHTML = function() {
            return document.getElementById("onetrust-banner-sdk") || (gr.insertPcHtml(),
            fr.insertAlertHtml()),
            Or.processedHtml || (Or.processedHtml = document.querySelector("#onetrust-consent-sdk").outerHTML),
            Or.processedHtml
        }
        ,
        this.getCSS = function() {
            return ar.processedCSS
        }
        ,
        this.setConsentProfile = function(e) {
            if (e.customPayload) {
                var t = e.customPayload;
                t.Interaction && Vt.writeCookieParam(Ee.OPTANON_CONSENT, Le, t.Interaction)
            }
            Or.setDataSubjectIdV2(e.identifier, e.isAnonymous),
            Or.synchroniseCookieWithPayload(e.purposes),
            Ir.executeOptanonWrapper()
        }
        ,
        this.InsertScript = function(e, t, o, n, r, i) {
            var s, a = null != n && void 0 !== n, l = a && void 0 !== n.ignoreGroupCheck && !0 === n.ignoreGroupCheck;
            if (Sn.canInsertForGroup(r, l) && !Bt.contains(Ht.srcExecGrps, r)) {
                Ht.srcExecGrpsTemp.push(r),
                a && void 0 !== n.deleteSelectorContent && !0 === n.deleteSelectorContent && Bt.empty(t);
                var c = document.createElement("script");
                switch (null != o && void 0 !== o && (s = !1,
                c.onload = c.onreadystatechange = function() {
                    s || this.readyState && "loaded" !== this.readyState && "complete" !== this.readyState || (s = !0,
                    o())
                }
                ),
                c.type = "text/javascript",
                c.src = e,
                i && (c.async = i),
                t) {
                case "head":
                    document.getElementsByTagName("head")[0].appendChild(c);
                    break;
                case "body":
                    document.getElementsByTagName("body")[0].appendChild(c);
                    break;
                default:
                    var d = document.getElementById(t);
                    d && (d.appendChild(c),
                    a && void 0 !== n.makeSelectorVisible && !0 === n.makeSelectorVisible && Bt.show(t))
                }
                if (a && void 0 !== n.makeElementsVisible)
                    for (var u = 0, p = n.makeElementsVisible; u < p.length; u++) {
                        var h = p[u];
                        Bt.show(h)
                    }
                if (a && void 0 !== n.deleteElements)
                    for (var g = 0, C = n.deleteElements; g < C.length; g++) {
                        h = C[g];
                        Bt.remove(h)
                    }
            }
        }
        ,
        this.InsertHtml = function(e, t, o, n, r) {
            var i = null != n && void 0 !== n
              , s = i && void 0 !== n.ignoreGroupCheck && !0 === n.ignoreGroupCheck;
            if (Sn.canInsertForGroup(r, s) && !Bt.contains(Ht.htmlExecGrps, r)) {
                if (Ht.htmlExecGrpsTemp.push(r),
                i && void 0 !== n.deleteSelectorContent && !0 === n.deleteSelectorContent && Bt.empty(t),
                Bt.appendTo(t, e),
                i && void 0 !== n.makeSelectorVisible && !0 === n.makeSelectorVisible && Bt.show(t),
                i && void 0 !== n.makeElementsVisible)
                    for (var a = 0, l = n.makeElementsVisible; a < l.length; a++) {
                        var c = l[a];
                        Bt.show(c)
                    }
                if (i && void 0 !== n.deleteElements)
                    for (var d = 0, u = n.deleteElements; d < u.length; d++) {
                        c = u[d];
                        Bt.remove(c)
                    }
                null != o && void 0 !== o && o()
            }
        }
        ,
        this.BlockGoogleAnalytics = function(e, t) {
            window["ga-disable-" + e] = !Sn.canInsertForGroup(t)
        }
    }
    var Hr, Fr, Rr, qr, Mr = (o(Fr = jr, Rr = Hr = Nr),
    Fr.prototype = null === Rr ? Object.create(Rr) : (Ur.prototype = Rr.prototype,
    new Ur),
    jr.prototype.Close = function(e) {
        Ir.closeBanner(!1),
        window.location.href = "http://otsdk//consentChanged"
    }
    ,
    jr.prototype.RejectAll = function(e) {
        Ir.rejectAllEvent(),
        window.location.href = "http://otsdk//consentChanged"
    }
    ,
    jr.prototype.AllowAll = function(e) {
        Ir.AllowAllV2(e),
        window.location.href = "http://otsdk//consentChanged"
    }
    ,
    jr.prototype.ToggleInfoDisplay = function() {
        Sr.toggleInfoDisplay()
    }
    ,
    jr);
    function Ur() {
        this.constructor = Fr
    }
    function jr() {
        var e = null !== Hr && Hr.apply(this, arguments) || this;
        return e.mobileOnlineURL = Ot.mobileOnlineURL,
        e
    }
    var zr, Kr = (Wr.prototype.syncConsentProfile = function(e, t, o) {
        void 0 === o && (o = !1),
        e ? (Ht.dsParams.id = e.trim(),
        Or.setDataSubjectIdV2(e)) : e = Ht.dsParams.id,
        o && (Ht.dsParams.isAnonymous = o),
        t = t || Ht.dsParams.token,
        e && t && dn.getConsentProfile(e, t).then(function(e) {
            return zr.consentProfileCallback(e)
        })
    }
    ,
    Wr.prototype.getConsentValue = function(e) {
        var t = null;
        switch (e) {
        case k[k.ACTIVE]:
        case k[k.ALWAYS_ACTIVE]:
            t = z.Active;
            break;
        case k[k.EXPIRED]:
        case k[k.OPT_OUT]:
        case k[k.PENDING]:
        case k[k.WITHDRAWN]:
            t = z.InActive
        }
        return t
    }
    ,
    Wr.prototype.isCookieGroup = function(e) {
        return !/IABV2|ISPV2|IFEV2|ISFV2/.test(e)
    }
    ,
    Wr.prototype.syncPreferences = function(e, t) {
        void 0 === t && (t = !1);
        var o = Vt.getCookie(Ee.ALERT_BOX_CLOSED)
          , n = o
          , r = !1
          , i = !0
          , s = !1
          , a = Bt.strToArr(Vt.readCookieParam(Ee.OPTANON_CONSENT, "groups"));
        if (e && e.preferences.length)
            for (var l = 0, c = e.preferences; l < c.length; l++) {
                var d = c[l]
                  , u = d.status === k[k.NO_CONSENT]
                  , p = Ot.domainGrps[d.id];
                if (p)
                    if (-1 < Ht.grpsSynced.indexOf(p) && (Ht.syncedValidGrp = !0),
                    u && a.length) {
                        for (var h = -1, g = 0; g < a.length; g++)
                            if (a[g].split(":")[0] === p) {
                                h = g;
                                break
                            }
                        -1 < h && (a.splice(h, 1),
                        Ht.grpsSynced.push(p))
                    } else if (!u && (!o || new Date(d.lastInteractionDate) > new Date(n))) {
                        var C = this.getConsentValue(d.status);
                        if (s = !0,
                        o = d.lastInteractionDate,
                        !t && this.isCookieGroup(p)) {
                            var y = p + ":" + C
                              , f = -1;
                            for (g = 0; g < a.length; g++) {
                                var v = a[g].split(":");
                                if (v[0] === p) {
                                    v[1] !== C && (a[g] = y,
                                    r = !0),
                                    f = g;
                                    break
                                }
                            }
                            -1 === f && (a.push(y),
                            r = !0)
                        }
                    }
            }
        else
            i = !1;
        return {
            alertBoxCookieVal: o,
            groupsConsent: a,
            profileFound: i,
            syncRequired: r,
            syncOnlyDate: s = s && !r
        }
    }
    ,
    Wr.prototype.hideBannerAndPc = function() {
        var e = Mt.isBannerVisible();
        e && Mt.hideBanner(),
        (e || Ht.isPCVisible) && Rn.hideConsentNoticeV2()
    }
    ,
    Wr.prototype.setOptanonConsentCookie = function(e, t) {
        if (e.syncRequired) {
            Vt.writeCookieParam(Ee.OPTANON_CONSENT, "groups", e.groupsConsent.toString());
            var o = Vt.getCookie(Ee.OPTANON_CONSENT);
            Vt.setCookie(Ee.OPTANON_CONSENT, o, t, !1, new Date(e.alertBoxCookieVal))
        }
    }
    ,
    Wr.prototype.setIabCookie = function(e, t, o) {
        o.syncGroups && o.syncGroups[Ht.syncGrpId] && o.syncGroups[Ht.syncGrpId].tcStringV2 ? Vt.getCookie(Ee.EU_PUB_CONSENT) !== o.syncGroups[Ht.syncGrpId].tcStringV2 && (e.syncRequired = !0,
        Vt.setCookie(Ee.EU_PUB_CONSENT, o.syncGroups[Ht.syncGrpId].tcStringV2, t, !1, new Date(e.alertBoxCookieVal))) : e.profileFound = !1
    }
    ,
    Wr.prototype.setAddtlVendorsCookie = function(e, t) {
        Nt.UseGoogleVendors && (Vt.getCookie(Ee.ADDITIONAL_CONSENT_STRING) || Vt.setCookie(Ee.ADDITIONAL_CONSENT_STRING, Ht.addtlConsentVersion, t, !1, new Date(e.alertBoxCookieVal)))
    }
    ,
    Wr.prototype.createTrans = function() {
        var e = Vt.readCookieParam(Ee.OPTANON_CONSENT, "iType");
        eo.createConsentTxn(!1, U[e], !1, !0)
    }
    ,
    Wr.prototype.updateGrpsDom = function() {
        for (var e = function(e) {
            var t = e.getAttribute("data-optanongroupid")
              , o = Xt.getGroupById(t)
              , n = !0
              , r = Bt.findIndex(Ht.groupsConsent, function(e) {
                return e.split(":")[0] === t
            });
            -1 < r && Ht.groupsConsent[r].split(":")[1] === z.InActive && (n = !1),
            Sn.toggleGrpElements(e, o, n),
            Sn.toogleSubGroupElement(e, n, !1, !0),
            Sn.toogleSubGroupElement(e, n, !0, !0)
        }, t = 0, o = Sn.getAllGroupElements(); t < o.length; t++)
            e(o[t])
    }
    ,
    Wr.prototype.updateVendorsDom = function() {
        Nt.IsIabEnabled && (Gn.updateIabVariableReference(),
        tr.toggleVendorConsent(),
        Ot.legIntSettings.PAllowLI && (Ot.legIntSettings.PShowLegIntBtn ? tr.updateVendorLegBtns() : tr.toggleVendorLi()))
    }
    ,
    Wr.prototype.consentProfileCallback = function(r) {
        return c(this, void 0, void 0, function() {
            var t, o, n;
            return C(this, function(e) {
                switch (e.label) {
                case 0:
                    return t = this.syncPreferences(r),
                    o = Nt.ReconsentFrequencyDays,
                    n = Qt.isIABCrossConsentEnabled(),
                    this.setOptanonConsentCookie(t, o),
                    Nt.IsIabEnabled && !n && this.setIabCookie(t, o, r),
                    t.syncOnlyDate && (Qt.syncAlertBoxCookie(t.alertBoxCookieVal),
                    Qt.syncCookieExpiry()),
                    t.syncRequired && t.profileFound ? (Ht.syncRequired = t.syncRequired,
                    Qt.syncAlertBoxCookie(t.alertBoxCookieVal),
                    this.setAddtlVendorsCookie(t, o),
                    this.hideBannerAndPc(),
                    hn.initGrpsAndHosts(),
                    !n && Nt.NtfyConfig.ShowNtfy && Qt.isAlertBoxClosedAndValid() ? [4, $n.getContent()] : [3, 2]) : [3, 3];
                case 1:
                    e.sent(),
                    $n.init(),
                    $n.changeState(),
                    e.label = 2;
                case 2:
                    return Nt.IsIabEnabled && (Qt.setIABCookieData(),
                    no.populateVendorAndPurposeFromCookieData()),
                    this.updateGrpsDom(),
                    this.updateVendorsDom(),
                    mo.setLandingPathParam(Ve),
                    En.substitutePlainTextScriptTags(),
                    Dn.updateGtmMacros(!0),
                    Ir.executeOptanonWrapper(),
                    [3, 4];
                case 3:
                    !t.profileFound && t.alertBoxCookieVal && this.createTrans(),
                    e.label = 4;
                case 4:
                    return [2]
                }
            })
        })
    }
    ,
    Wr);
    function Wr() {}
    var Jr, Yr = (Xr.prototype.removeCookies = function() {
        Vt.removePreview(),
        Vt.removeOptanon(),
        Vt.removeAlertBox(),
        Vt.removeIab2(),
        Vt.removeAddtlStr(),
        Vt.removeVariant(),
        Ht.isPreview && Jr.setPreviewCookie(),
        Ht.urlParams.get("otreset") && Ht.urlParams.set("otreset", "false");
        var e = window.location.pathname + "?" + Ht.urlParams.toString() + window.location.hash;
        Jr.replaceHistory(e)
    }
    ,
    Xr.prototype.setPreviewCookie = function() {
        var e = new Date;
        e.setTime(e.getTime() + 864e5);
        var t = Ht.geoFromUrl ? "&geo=" + Ht.geoFromUrl : ""
          , o = "expiry=" + e.toISOString() + t;
        Vt.setCookie(Ee.OT_PREVIEW, o, 1, !1)
    }
    ,
    Xr.prototype.bindStopPreviewEvent = function() {
        (window.attachEvent || window.addEventListener)("message", function(e) {
            return Jr.onMessage(e)
        })
    }
    ,
    Xr.prototype.replaceHistory = function(e) {
        history.pushState({}, "", e),
        location.reload()
    }
    ,
    Xr.prototype.onMessage = function(e) {
        "string" == typeof e.data && e.data === Jr.CLEAR_COOKIES && (Jr.removeCookies(),
        e.source && e.source.postMessage && e.source.postMessage(Jr.CLEARED_COOKIES, e.origin))
    }
    ,
    Xr);
    function Xr() {
        this.CLEAR_COOKIES = "CLEAR_OT_COOKIES",
        this.CLEARED_COOKIES = "CLEARED_OT_COOKIES"
    }
    function Qr(e) {
        if (e) {
            var t = window.atob(e);
            return Function('"use strict"; return ' + t)()
        }
    }
    Se.initPolyfill(),
    Vt = new Et,
    Mt = new jt,
    Ot = new xt,
    wo = new ln,
    Jr = new Yr,
    function() {
        var e, t = window.otStubData;
        if (t) {
            It.moduleInitializer = t.domainData,
            It.fp = It.moduleInitializer.TenantFeatures,
            Ht.isAMP = t.isAmp,
            Ht.dataDomainId = t.domainId,
            Ht.isPreview = t.isPreview,
            Ht.urlParams = t.urlParams,
            Ht.isV2Stub = t.isV2Stub || !1,
            Ot.gtmUpdatedinStub = t.gtmUpdated,
            t.isReset ? Jr.removeCookies() : t.isPreview && Jr.setPreviewCookie(),
            Ot.setBannerScriptElement(t.stubElement),
            Ot.setRegionRule(t.regionRule),
            It.fp.CookieV2TargetedTemplates && (Ot.conditionalLogicEnabled = !(null === (e = Ot.getRegionRule().Conditions) || void 0 === e || !e.length),
            Ot.conditionalLogicEnabled && (function() {
                for (var e = Ot.getRegionRule(), t = 0; t < e.Conditions.length; t++)
                    try {
                        if (Qr(e.Conditions[t].Expression))
                            return Ot.Condition = e.Conditions[t]
                    } catch (e) {
                        console.warn(e);
                        continue
                    }
                Ot.allConditionsFailed = !0
            }(),
            Ot.canUseConditionalLogic = !Ot.allConditionsFailed)),
            Ht.userLocation = t.userLocation,
            Ht.crossOrigin = t.crossOrigin,
            Ot.bannerDataParentURL = t.bannerBaseDataURL,
            Ot.mobileOnlineURL = y(Ot.mobileOnlineURL, t.mobileOnlineURL);
            var o = Ot.getRegionRule();
            Ot.multiVariantTestingEnabled = It.moduleInitializer.MultiVariantTestingEnabled && 0 < o.Variants.length && Mt.isDateCurrent(o.TestEndTime),
            Ot.otDataLayer = t.otDataLayer,
            Ht.grpsSynced = t.grpsSynced || [],
            Ht.isIabSynced = t.isIabSynced,
            Ht.isGacSynced = t.isGacSynced,
            Ht.syncRequired = t.isIabSynced || t.isGacSynced || t.grpsSynced && 0 < t.grpsSynced.length,
            Ht.consentPreferences = t.preferences,
            Ht.syncGrpId = t.syncGrpId,
            Ht.consentApi = t.consentApi,
            Ht.tenantId = t.tenantId,
            Ht.geoFromUrl = t.geoFromUrl,
            Ht.nonce = t.nonce,
            Ht.setAttributePolyfillIsActive = t.setAttributePolyfillIsActive,
            Ht.storageBaseURL = t.storageBaseURL,
            wo.populateLangSwitcherPlhdr(),
            window.otStubData = {
                userLocation: Ht.userLocation
            },
            window.OneTrustStub = null
        }
    }(),
    function() {
        c(this, void 0, void 0, function() {
            var t, o, n, r, i, s;
            return C(this, function(e) {
                switch (e.label) {
                case 0:
                    return Xt = new $t,
                    Sn = new An,
                    fn = new vn,
                    Gn = new On,
                    En = new wn,
                    Ir = new Lr,
                    Sr = new Ar,
                    gr = new Cr,
                    fr = new vr,
                    Vr = new Br,
                    In = new Ln,
                    ar = new lr,
                    go = new Co,
                    hn = new Cn,
                    Dn = new Hn,
                    wr = new xr,
                    Vo = new Bo,
                    Vn = new Bn,
                    zr = new Kr,
                    tr = new or,
                    dn = new un,
                    mn = new bn,
                    Rn = new Xn,
                    ur = new pr,
                    mr = new br,
                    It.moduleInitializer.MobileSDK ? qr = new Mr : Or = new Nr,
                    no = new ro,
                    t = Ot.getRegionRule(),
                    o = Ot.canUseConditionalLogic ? Ot.Condition.UseGoogleVendors : t.UseGoogleVendors,
                    "IAB2" !== Ot.getRegionRuleType() ? [3, 2] : [4, Promise.all([dn.getLangJson(), dn.fetchGvlObj(), o ? dn.fetchGoogleVendors() : Promise.resolve(null), dn.loadCMP()])];
                case 1:
                    return s = e.sent(),
                    n = s[0],
                    r = s[1],
                    i = s[2],
                    Ht.gvlObj = r,
                    Ht.addtlVendorsList = i ? i.vendors : null,
                    [3, 4];
                case 2:
                    return [4, dn.getLangJson()];
                case 3:
                    n = e.sent(),
                    e.label = 4;
                case 4:
                    return function(r) {
                        c(this, void 0, void 0, function() {
                            var t, o, n;
                            return C(this, function(e) {
                                switch (e.label) {
                                case 0:
                                    return window.OneTrust = window.Optanon = Object.assign({}, window.OneTrust, function(e) {
                                        var t, o = It.moduleInitializer.MobileSDK;
                                        t = o ? qr : Or;
                                        var n = {
                                            AllowAll: t.AllowAll,
                                            BlockGoogleAnalytics: t.BlockGoogleAnalytics,
                                            Close: t.Close,
                                            getCSS: t.getCSS,
                                            GetDomainData: t.GetDomainData,
                                            getGeolocationData: t.getGeolocationData,
                                            getHTML: t.getHTML,
                                            Init: t.Init,
                                            InitializeBanner: t.InitializeBanner,
                                            initializeCookiePolicyHtml: t.initCookiePolicyAndSettings,
                                            InsertHtml: t.InsertHtml,
                                            InsertScript: t.InsertScript,
                                            IsAlertBoxClosed: t.IsAlertBoxClosed,
                                            IsAlertBoxClosedAndValid: t.IsAlertBoxClosedAndValid,
                                            LoadBanner: t.LoadBanner,
                                            OnConsentChanged: Vo.OnConsentChanged,
                                            ReconsentGroups: t.ReconsentGroups,
                                            RejectAll: t.RejectAll,
                                            SetAlertBoxClosed: t.SetAlertBoxClosed,
                                            setGeoLocation: t.setGeoLocation,
                                            ToggleInfoDisplay: t.ToggleInfoDisplay,
                                            TriggerGoogleAnalyticsEvent: t.TriggerGoogleAnalyticsEvent,
                                            useGeoLocationService: t.useGeoLocationService,
                                            FetchAndDownloadPC: t.FetchAndDownloadPC,
                                            changeLanguage: t.changeLang,
                                            testLog: t.getTestLogData,
                                            UpdateConsent: t.updateSingularConsent,
                                            IsVendorServiceEnabled: t.vendorServiceEnabled
                                        };
                                        e.IsConsentLoggingEnabled && (n.getDataSubjectId = t.getDataSubjectId,
                                        n.setConsentProfile = t.setConsentProfile,
                                        n.setDataSubjectId = t.setDataSubjectIdV2,
                                        Ht.isV2Stub && (n.syncConsentProfile = zr.syncConsentProfile));
                                        o && (n.mobileOnlineURL = t.mobileOnlineURL,
                                        n.otCookieData = Ht.otCookieData);
                                        e.IsIabEnabled && (n.updateConsentFromCookies = Vo.updateConsentFromCookie,
                                        n.getPingRequest = no.getPingRequestForTcf,
                                        n.getVendorConsentsRequestV2 = no.getVendorConsentsRequestV2,
                                        n.showVendorsList = t.showVendorsList);
                                        return n
                                    }(r.DomainData)),
                                    Qt.initializeBannerVariables(r),
                                    so = new po,
                                    fo = new vo,
                                    eo = new to,
                                    Ao = new Lo,
                                    mo = new Po,
                                    rr = new ir,
                                    $n = new Zn,
                                    function() {
                                        var o = window.OTExternalConsent;
                                        if (o && o.consentedDate && (o.groups || o.tcString || o.addtlString)) {
                                            var n = []
                                              , e = o.groups.split(",");
                                            e.forEach(function(e) {
                                                var t = e.split(":");
                                                n.push({
                                                    lastInteractionDate: o.consentedDate,
                                                    status: "1" === t[1] ? k[k.ACTIVE] : k[k.OPT_OUT],
                                                    id: t[0]
                                                }),
                                                Ht.grpsSynced.push(t[0])
                                            }),
                                            Ht.consentPreferences = {
                                                preferences: n,
                                                syncGroups: null
                                            },
                                            Ht.syncRequired = !0,
                                            so.updateGroupsInCookie(Ee.OPTANON_CONSENT, e),
                                            Vt.setCookie(Ee.ALERT_BOX_CLOSED, o.consentedDate, 365),
                                            o.tcString && (Ht.isIabSynced = !0,
                                            Vt.setCookie(Ee.EU_PUB_CONSENT, o.tcString, 365)),
                                            o.addtlString && (Ht.isGacSynced = !0,
                                            Vt.setCookie(Ee.ADDITIONAL_CONSENT_STRING, "" + o.addtlString, 365))
                                        }
                                    }(),
                                    Ht.isPreview && (Qt.syncOtPreviewCookie(),
                                    Jr.bindStopPreviewEvent()),
                                    t = zr.syncPreferences(Ht.consentPreferences, !0),
                                    (Ht.syncRequired || t.syncRequired) && Qt.syncAlertBoxCookie(t.alertBoxCookieVal),
                                    Qt.syncCookieExpiry(),
                                    o = window.OneTrust.dataSubjectParams || {},
                                    (Ht.dsParams = o).id && Or.setDataSubjectIdV2(o.id, o.isAnonymous),
                                    Ot.multiVariantTestingEnabled && Ot.selectedVariant && Vt.setCookie(Ee.SELECTED_VARIANT, Ot.selectedVariant.Id, Nt.ReconsentFrequencyDays),
                                    [4, no.initializeIABModule()];
                                case 1:
                                    return e.sent(),
                                    window.OneTrust.Init(!0),
                                    [4, hn.fetchAssets()];
                                case 2:
                                    return (e.sent(),
                                    Vr.initBanner(),
                                    Vo.assetResolve(!0),
                                    ar.initialiseCssReferences(),
                                    n = Qt.isIABCrossConsentEnabled(),
                                    (Ht.syncedValidGrp || Ht.isIabSynced || Ht.isGacSynced) && !n && Nt.NtfyConfig.ShowNtfy && Qt.isAlertBoxClosedAndValid()) ? (Ht.ntfyRequired = !0,
                                    [4, $n.getContent()]) : [3, 4];
                                case 3:
                                    e.sent(),
                                    e.label = 4;
                                case 4:
                                    return n || window.OneTrust.LoadBanner(),
                                    [2]
                                }
                            })
                        })
                    }(n),
                    [2]
                }
            })
        })
    }()
}();
