
(function () {
    'use strict';

    // Generate or retrieve TabId from sessionStorage
    // sessionStorage is tab-specific (unlike localStorage which is shared)
    let tabId = sessionStorage.getItem('TabId');

    if (!tabId) {
        // Generate new unique ID for this tab
        tabId = 'tab_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
        sessionStorage.setItem('TabId', tabId);
        console.log('New TabId generated:', tabId);
    } else {
        console.log('Existing TabId found:', tabId);
    }

    // Intercept all fetch requests to add X-Tab-Id header
    const originalFetch = window.fetch;
    window.fetch = function (...args) {
        if (args[1]) {
            args[1].headers = args[1].headers || {};
            args[1].headers['X-Tab-Id'] = tabId;
        } else {
            args[1] = { headers: { 'X-Tab-Id': tabId } };
        }
        return originalFetch.apply(this, args);
    };

    // Intercept all XMLHttpRequest to add X-Tab-Id header
    const originalOpen = XMLHttpRequest.prototype.open;
    const originalSend = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function (...args) {
        this._url = args[1];
        return originalOpen.apply(this, args);
    };

    XMLHttpRequest.prototype.send = function (...args) {
        this.setRequestHeader('X-Tab-Id', tabId);
        return originalSend.apply(this, args);
    };

    // Add TabId to all form submissions
    document.addEventListener('submit', function (e) {
        const form = e.target;

        // Check if TabId hidden field already exists
        let tabIdField = form.querySelector('input[name="TabId"]');

        if (!tabIdField) {
            // Create hidden input for TabId
            tabIdField = document.createElement('input');
            tabIdField.type = 'hidden';
            tabIdField.name = 'TabId';
            tabIdField.value = tabId;
            form.appendChild(tabIdField);
        } else {
            // Update existing field
            tabIdField.value = tabId;
        }
    });

    // Add TabId header to all AJAX requests (jQuery)
    if (window.jQuery) {
        jQuery.ajaxSetup({
            beforeSend: function (xhr) {
                xhr.setRequestHeader('X-Tab-Id', tabId);
            }
        });
    }

    console.log('Tab detection initialized with TabId:', tabId);
})();