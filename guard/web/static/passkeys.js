/* InitStack Guard: passkey sign-in, passkey registration and passkey confirmation.

   Served from /static because the page CSP forbids inline script. This file only drives the browser's
   WebAuthn calls; every check (challenge, origin, RP ID, signature, user verification, sign count) happens
   on the server. Requests are JSON posts that carry the page's CSRF token in X-CSRF-Token.
   Feedback follows DESIGN_SKILL.md: the button reacts as soon as it is pressed, status and error text
   appear right next to it, and nothing locks the page while the device asks for a fingerprint. */
(function () {
  "use strict";

  var supported = !!(window.PublicKeyCredential && navigator.credentials &&
                     navigator.credentials.create && navigator.credentials.get);

  function byId(id) { return document.getElementById(id); }
  function show(el, text) { if (el) { if (text !== undefined) { el.textContent = text; } el.hidden = false; } }
  function hide(el) { if (el) { el.hidden = true; } }

  function busy(button, on, label) {
    if (!button) { return; }
    if (on) {
      button.dataset.label = button.textContent;
      button.textContent = label;
      button.disabled = true;
      button.setAttribute("aria-busy", "true");
    } else {
      button.textContent = button.dataset.label || button.textContent;
      button.disabled = false;
      button.removeAttribute("aria-busy");
    }
  }

  function b64uToBuf(text) {
    var s = text.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) { s += "="; }
    var bin = atob(s), bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) { bytes[i] = bin.charCodeAt(i); }
    return bytes.buffer;
  }

  function bufToB64u(buf) {
    var bytes = new Uint8Array(buf), s = "";
    for (var i = 0; i < bytes.length; i++) { s += String.fromCharCode(bytes[i]); }
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function creationOptions(o) {
    o.challenge = b64uToBuf(o.challenge);
    o.user.id = b64uToBuf(o.user.id);
    (o.excludeCredentials || []).forEach(function (c) { c.id = b64uToBuf(c.id); });
    return o;
  }

  function requestOptions(o) {
    o.challenge = b64uToBuf(o.challenge);
    (o.allowCredentials || []).forEach(function (c) { c.id = b64uToBuf(c.id); });
    return o;
  }

  function common(cred) {
    var out = {
      id: cred.id,
      rawId: bufToB64u(cred.rawId),
      type: cred.type,
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {}
    };
    if (cred.authenticatorAttachment) { out.authenticatorAttachment = cred.authenticatorAttachment; }
    return out;
  }

  function registrationJson(cred) {
    var out = common(cred), r = cred.response;
    out.response = {
      clientDataJSON: bufToB64u(r.clientDataJSON),
      attestationObject: bufToB64u(r.attestationObject),
      transports: r.getTransports ? r.getTransports() : []
    };
    return out;
  }

  function assertionJson(cred) {
    var out = common(cred), r = cred.response;
    out.response = {
      clientDataJSON: bufToB64u(r.clientDataJSON),
      authenticatorData: bufToB64u(r.authenticatorData),
      signature: bufToB64u(r.signature)
    };
    if (r.userHandle && r.userHandle.byteLength) { out.response.userHandle = bufToB64u(r.userHandle); }
    return out;
  }

  function postJson(url, body, token) {
    return fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "Accept": "application/json", "X-CSRF-Token": token },
      body: JSON.stringify(body)
    }).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (json) {
        return { ok: response.ok, status: response.status, body: json };
      });
    });
  }

  function serverError(result) {
    var message = result.body && result.body.error && result.body.error.message;
    var err = new Error(message || "The server refused the request.");
    err.userMessage = message || "The server refused the request. Reload the page and try again.";
    return err;
  }

  function describe(err) {
    if (err && err.userMessage) { return err.userMessage; }
    if (err && err.name === "NotAllowedError") { return "The request was cancelled or timed out. Try again."; }
    if (err && err.name === "InvalidStateError") { return "This device already has a passkey for your account."; }
    if (err && err.name === "SecurityError") { return "This page cannot use passkeys here. Check that you opened it at its real address."; }
    return "Something went wrong. Try again.";
  }

  function sameSitePath(path) { return typeof path === "string" && /^\/(?!\/)/.test(path) ? path : "/"; }

  /* ---- sign-in page ------------------------------------------------------------------------ */
  var signin = byId("passkey-signin");
  if (signin) {
    if (!supported) {
      show(byId("passkey-unsupported"));
    } else {
      show(signin);
      show(byId("passkey-divider"));
      var signinButton = byId("passkey-signin-button");
      var signinError = byId("passkey-error");
      var signinToken = signin.getAttribute("data-csrf-token");
      signinButton.addEventListener("click", function () {
        hide(signinError);
        busy(signinButton, true, "Waiting for your device\u2026");
        postJson("/login/passkey/options", {}, signinToken).then(function (r) {
          if (!r.ok) { throw serverError(r); }
          return navigator.credentials.get({ publicKey: requestOptions(r.body.data) });
        }).then(function (cred) {
          if (!cred) { throw new Error("no credential"); }
          return postJson("/login/passkey/verify", { credential: assertionJson(cred) }, signinToken);
        }).then(function (r) {
          if (!r.ok) { throw serverError(r); }
          window.location.assign(sameSitePath(r.body.data && r.body.data.redirect));
        }).catch(function (err) {
          show(signinError, describe(err));
          busy(signinButton, false);
        });
      });
    }
  }

  /* ---- account page ------------------------------------------------------------------------ */
  var section = byId("passkeys");
  if (section) {
    var token = section.getAttribute("data-csrf-token");
    var status = byId("passkey-status");
    var failure = byId("passkey-error");
    var addForm = byId("passkey-add");
    var reauthButton = byId("passkey-reauth");

    if (!supported) {
      show(byId("passkey-unsupported"));
    } else {
      show(addForm);
      show(reauthButton);
    }

    if (addForm && supported) {
      addForm.addEventListener("submit", function (event) {
        event.preventDefault();
        var name = addForm.elements.name.value;
        var button = addForm.querySelector("button[type=submit]");
        hide(failure);
        hide(status);
        busy(button, true, "Waiting for your device\u2026");
        postJson("/api/v1/passkeys/register/options", { name: name }, token).then(function (r) {
          if (!r.ok) { throw serverError(r); }
          return navigator.credentials.create({ publicKey: creationOptions(r.body.data) });
        }).then(function (cred) {
          if (!cred) { throw new Error("no credential"); }
          return postJson("/api/v1/passkeys/register/verify",
                          { credential: registrationJson(cred), name: name }, token);
        }).then(function (r) {
          if (!r.ok) { throw serverError(r); }
          window.location.assign("/account?msg=passkey_added");
        }).catch(function (err) {
          show(failure, describe(err));
          busy(button, false);
        });
      });
    }

    if (reauthButton && supported) {
      reauthButton.addEventListener("click", function () {
        hide(failure);
        hide(status);
        busy(reauthButton, true, "Waiting for your device\u2026");
        postJson("/api/v1/reauth/passkey/options", {}, token).then(function (r) {
          if (!r.ok) { throw serverError(r); }
          return navigator.credentials.get({ publicKey: requestOptions(r.body.data) });
        }).then(function (cred) {
          if (!cred) { throw new Error("no credential"); }
          return postJson("/api/v1/reauth/passkey/verify", { credential: assertionJson(cred) }, token);
        }).then(function (r) {
          if (!r.ok) { throw serverError(r); }
          window.location.assign("/account?msg=reauth_passkey_ok");
        }).catch(function (err) {
          show(failure, describe(err));
          busy(reauthButton, false);
        });
      });
    }
  }
})();
