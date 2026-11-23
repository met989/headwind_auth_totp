/**
 * Headwind MDM - 2FA TOTP Authentication & Management Hook Script
 * Non-invasive integration for Headwind MDM.
 * Loaded via: <script src="/auth-totp/totp-hook.js" defer></script>
 */
(function () {
    'use strict';

    var API_BASE = '/auth-totp/api';
    var isChecking = false;
    var isVerified = false;
    var currentUserData = null;
    var activeLoginModal = null;
    var activeAdminModal = null;
    var currentRenderedMode = null; // 'setup' | 'verify'

    // 1. Ensure CSS Stylesheet is loaded
    function ensureStyles() {
        if (!document.getElementById('hmdm-totp-styles')) {
            var link = document.createElement('link');
            link.id = 'hmdm-totp-styles';
            link.rel = 'stylesheet';
            link.href = '/auth-totp/css/totp-style.css';
            document.head.appendChild(link);
        }
    }

    // 2. Query Status from Server
    function checkTotpStatus(callback) {
        // If modal is actively displayed and user is interacting with it, do not interrupt
        if (activeLoginModal && currentRenderedMode) {
            if (typeof callback === 'function') callback(null, currentUserData);
            return;
        }

        if (isChecking) return;
        isChecking = true;

        fetch(API_BASE + '/status?_t=' + Date.now(), {
            method: 'GET',
            credentials: 'same-origin',
            headers: { 'Accept': 'application/json' }
        })
            .then(function (res) { return res.json(); })
            .then(function (data) {
                isChecking = false;
                if (data && data.status === 'OK' && data.data) {
                    var d = data.data;
                    currentUserData = d;

                    if (!d.authenticated) {
                        // Not logged in to Headwind MDM
                        sessionStorage.removeItem('hmdm_2fa_pending');
                        sessionStorage.removeItem('hmdm_2fa_verified');
                        removeLoginModal();
                        removeSidebarMenuItem();
                        isVerified = false;
                    } else {
                        // User is authenticated
                        if (d.isAdmin) {
                            injectSidebarMenuItem();
                        } else {
                            removeSidebarMenuItem();
                        }

                        // Check if 2FA is required and verified
                        if (d.enabled && !d.verified) {
                            isVerified = false;
                            sessionStorage.setItem('hmdm_2fa_pending', '1');
                            sessionStorage.removeItem('hmdm_2fa_verified');
                            showTotpModal(d);
                        } else {
                            isVerified = true;
                            sessionStorage.removeItem('hmdm_2fa_pending');
                            sessionStorage.setItem('hmdm_2fa_verified', '1');
                            removeLoginModal();
                        }
                    }
                    if (typeof callback === 'function') callback(null, d);
                }
            })
            .catch(function (err) {
                isChecking = false;
                if (typeof callback === 'function') callback(err);
            });
    }

    // -------------------------------------------------------------
    // 3. SIDEBAR MENU INTEGRATION ("Funzioni" / Functions)
    // -------------------------------------------------------------
    function injectSidebarMenuItem() {
        if (!currentUserData || !currentUserData.isAdmin) {
            removeSidebarMenuItem();
            return;
        }

        var existing = document.querySelector('.hmdm-totp-sidebar-link');
        var tree = document.querySelector('mat-tree');
        if (!tree) {
            if (existing) existing.remove();
            return;
        }

        var nodes = tree.querySelectorAll('mat-tree-node');
        if (!nodes || nodes.length === 0) return;

        var functionsNode = null;
        var lastChildNode = null;

        for (var i = 0; i < nodes.length; i++) {
            var n = nodes[i];
            var textEl = n.querySelector('.menu-text');
            if (!textEl) continue;
            var txt = textEl.textContent.trim().toLowerCase();
            if (txt === 'funzioni' || txt === 'functions' || txt === 'menu.functions') {
                functionsNode = n;
                for (var j = i + 1; j < nodes.length; j++) {
                    var sibling = nodes[j];
                    var level = sibling.getAttribute('aria-level');
                    if (level === '2' && !sibling.classList.contains('hmdm-totp-sidebar-link')) {
                        lastChildNode = sibling;
                    } else if (level !== '2') {
                        break;
                    }
                }
                break;
            }
        }

        if (!functionsNode) {
            if (existing) existing.remove();
            return;
        }

        // Check if "Funzioni" is expanded
        var isExpanded = false;
        var icon = functionsNode.querySelector('mat-icon');
        if (icon && icon.textContent.trim() === 'expand_more') isExpanded = true;
        var btn = functionsNode.querySelector('button');
        if (btn && btn.getAttribute('aria-expanded') === 'true') isExpanded = true;
        if (lastChildNode) isExpanded = true;

        if (!isExpanded) {
            if (existing) existing.remove();
            return;
        }

        if (existing) return; // Already present in tree

        var item;
        if (lastChildNode) {
            item = lastChildNode.cloneNode(true);
            item.classList.remove('active', 'node-locked', 'hmdm-remote-sidebar-link');
            item.classList.add('hmdm-totp-sidebar-link');
            item.removeAttribute('href');
            item.removeAttribute('routerlink');

            var lockBadge = item.querySelector('.badge-locked');
            if (lockBadge) lockBadge.remove();

            var iconEl = item.querySelector('.menu-icon, mat-icon');
            if (iconEl) {
                iconEl.textContent = 'security';
            }

            var labelEl = item.querySelector('.menu-text');
            if (labelEl) {
                labelEl.textContent = 'Two-Factor Auth';
            }
        } else {
            item = document.createElement('mat-tree-node');
            item.className = 'mat-tree-node hmdm-totp-sidebar-link';
            item.setAttribute('role', 'treeitem');
            item.setAttribute('aria-level', '2');
            item.setAttribute('tabindex', '-1');
            item.innerHTML =
                '<mat-icon role="img" class="mat-icon notranslate material-icons mat-ligature-font menu-icon" aria-hidden="true">security</mat-icon>' +
                '<span class="menu-text">Two-Factor Auth</span>';
        }

        item.style.cursor = 'pointer';

        item.addEventListener('mouseenter', function () {
            item.style.backgroundColor = 'var(--mat-sys-primary, #1976d2)';
            item.style.color = 'var(--mat-sys-on-primary, #ffffff)';
            var ic = item.querySelector('.menu-icon');
            if (ic) ic.style.color = 'var(--mat-sys-on-primary, #ffffff)';
        });
        item.addEventListener('mouseleave', function () {
            item.style.backgroundColor = '';
            item.style.color = '';
            var ic = item.querySelector('.menu-icon');
            if (ic) ic.style.color = '';
        });

        item.addEventListener('click', function (e) {
            e.preventDefault();
            e.stopPropagation();
            openAdminModal();
        });

        if (lastChildNode && lastChildNode.parentNode) {
            lastChildNode.parentNode.insertBefore(item, lastChildNode.nextSibling);
        } else if (functionsNode && functionsNode.parentNode) {
            functionsNode.parentNode.insertBefore(item, functionsNode.nextSibling);
        }
    }

    function removeSidebarMenuItem() {
        var existing = document.querySelector('.hmdm-totp-sidebar-link');
        if (existing && existing.parentNode) {
            existing.parentNode.removeChild(existing);
        }
    }

    // -------------------------------------------------------------
    // 4. ADMIN 2FA MANAGEMENT MODAL (HEADWIND MDM NATIVE LOOK)
    // -------------------------------------------------------------
    var cachedUsersList = [];

    function openAdminModal() {
        ensureStyles();
        if (activeAdminModal) return;

        var backdrop = document.createElement('div');
        backdrop.id = 'hmdm-totp-admin-backdrop';

        var modal = document.createElement('div');
        modal.className = 'hmdm-totp-admin-modal';
        modal.innerHTML =
            '<div class="hmdm-card-top-bar">' +
            '<div class="hmdm-card-title-group">' +
            '<div style="display:flex;align-items:center;gap:12px;">' +
            '<img src="/images/logo.png" style="width:32px;height:32px;object-fit:contain;" alt="Logo">' +
            '<h2 class="hmdm-card-title">Two-Factor Authentication (TOTP)</h2>' +
            '</div>' +
            '<div class="hmdm-search-box">' +
            '<mat-icon role="img" class="mat-icon notranslate material-icons mat-ligature-font" style="font-size:20px;width:20px;height:20px;color:#546e7a;">search</mat-icon>' +
            '<input type="text" class="hmdm-search-input" id="hmdm-totp-search-input" placeholder="Search user by name or username...">' +
            '</div>' +
            '</div>' +
            '<div class="hmdm-card-actions">' +
            '<button type="button" class="hmdm-btn-primary" id="hmdm-admin-refresh-btn">' +
            '<mat-icon role="img" class="mat-icon notranslate material-icons mat-ligature-font">refresh</mat-icon>' +
            '<span>Refresh</span>' +
            '</button>' +
            '<button type="button" class="hmdm-btn-outline" id="hmdm-admin-close-btn" title="Back to Headwind MDM">' +
            '<mat-icon role="img" class="mat-icon notranslate material-icons mat-ligature-font">arrow_back</mat-icon>' +
            '<span>Back to Headwind MDM</span>' +
            '</button>' +
            '</div>' +
            '</div>' +
            '<div class="hmdm-card-sub-bar">' +
            '<div class="hmdm-sub-info">' +
            '<mat-icon role="img" class="mat-icon notranslate material-icons mat-ligature-font" style="font-size:16px;width:16px;height:16px;color:#546e7a;">info</mat-icon>' +
            '<span>Two-factor authentication (TOTP) is <b>disabled by default</b>. Toggle the switch to require it for individual users.</span>' +
            '</div>' +
            '<div id="hmdm-totp-user-count" style="font-weight: 500;">Loading...</div>' +
            '</div>' +
            '<div class="hmdm-table-scroll-wrap">' +
            '<table class="hmdm-native-table">' +
            '<thead>' +
            '<tr>' +
            '<th style="width: 140px;">Status</th>' +
            '<th class="hmdm-th-sort" id="hmdm-th-user">User <span class="sort-arrow">↕</span></th>' +
            '<th class="hmdm-th-sort" id="hmdm-th-name">Full Name <span class="sort-arrow">↕</span></th>' +
            '<th>Email</th>' +
            '<th style="width: 120px;">Role</th>' +
            '<th style="text-align: center; width: 170px;">Two-Factor Auth</th>' +
            '<th style="text-align: center; width: 150px;">Actions</th>' +
            '</tr>' +
            '</thead>' +
            '<tbody id="hmdm-admin-users-tbody">' +
            '<tr><td colspan="7" style="text-align:center; padding: 24px; color:#546e7a;">Loading users...</td></tr>' +
            '</tbody>' +
            '</table>' +
            '</div>' +
            '<div class="hmdm-card-footer">' +
            '<div style="font-size: 12px; color: #546e7a;">' +
            'Supports any standard RFC 6238 TOTP app (Google Authenticator, Microsoft Authenticator, 1Password, Authy)' +
            '</div>' +
            '<button type="button" class="hmdm-btn-outline" id="hmdm-admin-bottom-close-btn">' +
            '<mat-icon role="img" class="mat-icon notranslate material-icons mat-ligature-font" style="font-size:16px;width:16px;height:16px;">arrow_back</mat-icon>' +
            '<span>Back to Headwind MDM</span>' +
            '</button>' +
            '</div>';

        backdrop.appendChild(modal);
        document.body.appendChild(backdrop);
        activeAdminModal = backdrop;

        // Close bindings
        var closeFn = function () {
            if (activeAdminModal && activeAdminModal.parentNode) {
                activeAdminModal.parentNode.removeChild(activeAdminModal);
                activeAdminModal = null;
            }
        };
        document.getElementById('hmdm-admin-close-btn').onclick = closeFn;
        document.getElementById('hmdm-admin-bottom-close-btn').onclick = closeFn;
        backdrop.onclick = function (e) {
            if (e.target === backdrop) closeFn();
        };

        document.getElementById('hmdm-admin-refresh-btn').onclick = function () {
            loadAdminUsers();
        };

        var searchInput = document.getElementById('hmdm-totp-search-input');
        if (searchInput) {
            searchInput.oninput = function () {
                var query = searchInput.value.toLowerCase().trim();
                renderFilteredUsers(query);
            };
        }

        var sortAsc = true;
        var thUser = document.getElementById('hmdm-th-user');
        var thName = document.getElementById('hmdm-th-name');
        if (thUser) {
            thUser.onclick = function () {
                sortAsc = !sortAsc;
                cachedUsersList.sort(function (a, b) {
                    var r = (a.username || '').localeCompare(b.username || '');
                    return sortAsc ? r : -r;
                });
                var q = (searchInput && searchInput.value) ? searchInput.value.toLowerCase().trim() : '';
                renderFilteredUsers(q);
            };
        }
        if (thName) {
            thName.onclick = function () {
                sortAsc = !sortAsc;
                cachedUsersList.sort(function (a, b) {
                    var r = (a.name || '').localeCompare(b.name || '');
                    return sortAsc ? r : -r;
                });
                var q = (searchInput && searchInput.value) ? searchInput.value.toLowerCase().trim() : '';
                renderFilteredUsers(q);
            };
        }

        loadAdminUsers();
    }

    function loadAdminUsers() {
        var tbody = document.getElementById('hmdm-admin-users-tbody');
        var countEl = document.getElementById('hmdm-totp-user-count');
        if (!tbody) return;
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding: 24px; color:#546e7a;">Loading users...</td></tr>';
        if (countEl) countEl.textContent = 'Loading...';

        fetch(API_BASE + '/admin/users?_t=' + Date.now(), {
            method: 'GET',
            credentials: 'same-origin',
            headers: { 'Accept': 'application/json' }
        })
            .then(function (res) { return res.json(); })
            .then(function (resp) {
                if (resp && resp.status === 'OK' && Array.isArray(resp.data)) {
                    cachedUsersList = resp.data;
                    var searchInput = document.getElementById('hmdm-totp-search-input');
                    var query = (searchInput && searchInput.value) ? searchInput.value.toLowerCase().trim() : '';
                    renderFilteredUsers(query);
                } else {
                    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding: 24px; color:#ba1a1a;">Failed to load users list.</td></tr>';
                }
            })
            .catch(function () {
                tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding: 24px; color:#ba1a1a;">Server connection error.</td></tr>';
            });
    }

    function renderFilteredUsers(query) {
        var filtered = cachedUsersList;
        if (query) {
            filtered = cachedUsersList.filter(function (u) {
                var login = (u.username || '').toLowerCase();
                var name = (u.name || '').toLowerCase();
                var email = (u.email || '').toLowerCase();
                return login.indexOf(query) !== -1 || name.indexOf(query) !== -1 || email.indexOf(query) !== -1;
            });
        }
        renderAdminUsersTable(filtered);
    }

    function renderAdminUsersTable(users) {
        var tbody = document.getElementById('hmdm-admin-users-tbody');
        var countEl = document.getElementById('hmdm-totp-user-count');
        if (!tbody) return;
        tbody.innerHTML = '';

        if (countEl) {
            countEl.textContent = 'Total: ' + users.length + ' user' + (users.length === 1 ? '' : 's');
        }

        if (users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding: 24px; color:#546e7a;">No users found.</td></tr>';
            return;
        }

        users.forEach(function (u) {
            var tr = document.createElement('tr');
            tr.id = 'hmdm-user-row-' + u.username;

            // 1. Status with Native Diamond ◆
            var tdStatus = document.createElement('td');
            tdStatus.id = 'hmdm-status-cell-' + u.username;
            updateStatusDiamond(tdStatus, u.enabled, u.configured);
            tr.appendChild(tdStatus);

            // 2. Username
            var tdUser = document.createElement('td');
            tdUser.innerHTML = '<span style="font-weight: 500;">' + escapeHtml(u.username) + '</span>';
            tr.appendChild(tdUser);

            // 3. Full Name
            var tdName = document.createElement('td');
            tdName.textContent = u.name || '-';
            tr.appendChild(tdName);

            // 4. Email
            var tdEmail = document.createElement('td');
            tdEmail.style.color = '#546e7a';
            tdEmail.textContent = u.email || '-';
            tr.appendChild(tdEmail);

            // 5. Role Badge
            var tdRole = document.createElement('td');
            var roleLabel = u.superadmin ? 'Super-Admin' : (u.role || 'Admin');
            tdRole.innerHTML = '<span style="display:inline-block;padding:2px 8px;border-radius:4px;background:#eef3f7;color:#4c788c;font-weight:500;font-size:12px;">' + escapeHtml(roleLabel) + '</span>';
            tr.appendChild(tdRole);

            // 6. Slide Toggle (Two-Factor Auth)
            var tdToggle = document.createElement('td');
            tdToggle.style.textAlign = 'center';
            var switchLabel = document.createElement('label');
            switchLabel.className = 'hmdm-slide-toggle';
            var checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.checked = !!u.enabled;
            var slider = document.createElement('span');
            slider.className = 'hmdm-slide-toggle-slider';

            checkbox.onchange = function () {
                var newEnabled = checkbox.checked;
                checkbox.disabled = true;
                toggleUser2Fa(u.username, newEnabled, function (err) {
                    checkbox.disabled = false;
                    if (err) {
                        checkbox.checked = !newEnabled;
                        showToast('Error during update: ' + (err.message || 'Please try again'), true);
                    } else {
                        u.enabled = newEnabled;
                        updateStatusDiamond(tdStatus, u.enabled, u.configured);
                        updateResetBtn(btnReset, u.enabled, u.configured);
                        showToast('Two-factor authentication ' + (newEnabled ? 'enabled' : 'disabled') + ' for ' + (u.name || u.username), false);
                    }
                });
            };

            switchLabel.appendChild(checkbox);
            switchLabel.appendChild(slider);
            tdToggle.appendChild(switchLabel);
            tr.appendChild(tdToggle);

            // 7. Reset Action Button
            var tdActions = document.createElement('td');
            tdActions.style.textAlign = 'center';
            var btnReset = document.createElement('button');
            btnReset.type = 'button';
            btnReset.className = 'hmdm-action-btn-reset';
            btnReset.innerHTML = '<mat-icon role="img" class="mat-icon notranslate material-icons mat-ligature-font">restart_alt</mat-icon><span>Reset 2FA</span>';
            updateResetBtn(btnReset, u.enabled, u.configured);

            btnReset.onclick = function () {
                var confirmMsg = 'Are you sure you want to reset 2FA for user "' + (u.name || u.username) + '" (' + u.username + ')?\n\n' +
                    'Upon next login, they will need to link a new QR code on their smartphone.';
                if (window.confirm(confirmMsg)) {
                    btnReset.disabled = true;
                    btnReset.innerHTML = '<span>Resetting...</span>';
                    resetUser2Fa(u.username, function (err) {
                        if (err) {
                            updateResetBtn(btnReset, u.enabled, u.configured);
                            showToast('Error during reset: ' + (err.message || 'Please try again'), true);
                        } else {
                            u.configured = false;
                            updateStatusDiamond(tdStatus, u.enabled, false);
                            updateResetBtn(btnReset, u.enabled, false);
                            showToast('2FA reset successfully for ' + (u.name || u.username) + '!', false);
                        }
                    });
                }
            };

            tdActions.appendChild(btnReset);
            tr.appendChild(tdActions);

            tbody.appendChild(tr);
        });
    }

    function updateStatusDiamond(container, enabled, configured) {
        if (!enabled) {
            container.innerHTML =
                '<div class="hmdm-status-cell">' +
                '<span class="hmdm-status-diamond hmdm-status-diamond-off">◆</span>' +
                '<span class="hmdm-status-label" style="color:#78909c;">Disabled</span>' +
                '</div>';
        } else if (!configured) {
            container.innerHTML =
                '<div class="hmdm-status-cell">' +
                '<span class="hmdm-status-diamond hmdm-status-diamond-pending">◆</span>' +
                '<span class="hmdm-status-label" style="color:#d97706;">Pending QR</span>' +
                '</div>';
        } else {
            container.innerHTML =
                '<div class="hmdm-status-cell">' +
                '<span class="hmdm-status-diamond hmdm-status-diamond-active">◆</span>' +
                '<span class="hmdm-status-label" style="color:#2e7d32;">Active</span>' +
                '</div>';
        }
    }

    function updateResetBtn(btn, enabled, configured) {
        if (configured || enabled) {
            btn.disabled = false;
            btn.innerHTML = '<mat-icon role="img" class="mat-icon notranslate material-icons mat-ligature-font">restart_alt</mat-icon><span>Reset 2FA</span>';
            btn.title = 'Reset 2FA secret to allow linking a new device via QR Code';
        } else {
            btn.disabled = true;
            btn.innerHTML = '<mat-icon role="img" class="mat-icon notranslate material-icons mat-ligature-font">restart_alt</mat-icon><span>Reset 2FA</span>';
            btn.title = '2FA is not enabled for this user';
        }
    }

    function toggleUser2Fa(username, enabled, callback) {
        fetch(API_BASE + '/admin/toggle', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({ username: username, enabled: enabled })
        })
            .then(function (res) { return res.json(); })
            .then(function (resp) {
                if (resp && resp.status === 'OK') {
                    callback(null);
                } else {
                    callback(new Error(resp.message || 'Operation failed'));
                }
            })
            .catch(function (err) {
                callback(err);
            });
    }

    function resetUser2Fa(username, callback) {
        fetch(API_BASE + '/admin/reset', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({ username: username })
        })
            .then(function (res) { return res.json(); })
            .then(function (resp) {
                if (resp && resp.status === 'OK') {
                    callback(null);
                } else {
                    callback(new Error(resp.message || 'Reset failed'));
                }
            })
            .catch(function (err) {
                callback(err);
            });
    }

    function showToast(message, isError) {
        var existing = document.getElementById('hmdm-totp-toast');
        if (existing) existing.remove();

        var toast = document.createElement('div');
        toast.id = 'hmdm-totp-toast';
        toast.className = 'hmdm-native-toast ' + (isError ? 'hmdm-native-toast-error' : 'hmdm-native-toast-success');
        toast.textContent = message;
        document.body.appendChild(toast);

        setTimeout(function () {
            toast.style.opacity = '0';
            setTimeout(function () {
                if (toast.parentNode) toast.parentNode.removeChild(toast);
            }, 300);
        }, 4000);
    }

    // -------------------------------------------------------------
    // 5. LOGIN 2FA MODAL (100% Native Headwind MDM Skin & Pre-Gate)
    // -------------------------------------------------------------
    function showPreGate() {
        ensureStyles();
        if (activeLoginModal) return;

        var backdrop = document.createElement('div');
        backdrop.id = 'hmdm-totp-backdrop';
        backdrop.innerHTML =
            '<div class="hmdm-auth-container">' +
            '<div class="hmdm-auth-logo-header">' +
            '<img src="/images/logo.png" class="hmdm-auth-logo-img" alt="Headwind MDM">' +
            '<h1 class="hmdm-auth-brand-name">Headwind MDM</h1>' +
            '</div>' +
            '<div class="hmdm-auth-card" style="text-align: center; padding: 48px 32px;">' +
            '<div class="hmdm-spinner" style="margin: 0 auto 16px auto;"></div>' +
            '<div style="font-size: 14px; color: #546e7a; font-weight: 500;">Verifying account security...</div>' +
            '</div>' +
            '<div class="hmdm-footer-copyright">Headwind MDM — Mobile Device Management</div>' +
            '</div>';
        document.body.appendChild(backdrop);
        activeLoginModal = backdrop;
    }

    function showTotpModal(statusData) {
        ensureStyles();

        var targetMode = !statusData.configured ? 'setup' : 'verify';

        // CRITICAL: If the modal is already displayed in this exact mode,
        // DO NOT re-render it, do not touch the DOM, do not re-fetch /setup!
        // This gives the user stable, uninterrupted time to scan the QR and enter the code.
        if (activeLoginModal && currentRenderedMode === targetMode) {
            return;
        }

        currentRenderedMode = targetMode;

        if (!activeLoginModal) {
            var backdrop = document.createElement('div');
            backdrop.id = 'hmdm-totp-backdrop';
            backdrop.innerHTML =
                '<div class="hmdm-auth-container">' +
                '<div class="hmdm-auth-logo-header">' +
                '<img src="/images/logo.png" class="hmdm-auth-logo-img" alt="Headwind MDM">' +
                '<h1 class="hmdm-auth-brand-name">Headwind MDM</h1>' +
                '</div>' +
                '<div class="hmdm-auth-card" id="hmdm-totp-card-root"></div>' +
                '<div class="hmdm-footer-copyright">Headwind MDM — Mobile Device Management</div>' +
                '</div>';
            document.body.appendChild(backdrop);
            activeLoginModal = backdrop;
        } else {
            var cardRoot = activeLoginModal.querySelector('#hmdm-totp-card-root');
            if (!cardRoot) {
                var authContainer = activeLoginModal.querySelector('.hmdm-auth-container');
                if (authContainer) {
                    authContainer.innerHTML =
                        '<div class="hmdm-auth-logo-header">' +
                        '<img src="/images/logo.png" class="hmdm-auth-logo-img" alt="Headwind MDM">' +
                        '<h1 class="hmdm-auth-brand-name">Headwind MDM</h1>' +
                        '</div>' +
                        '<div class="hmdm-auth-card" id="hmdm-totp-card-root"></div>' +
                        '<div class="hmdm-footer-copyright">Headwind MDM — Mobile Device Management</div>';
                }
            }
        }

        var card = document.getElementById('hmdm-totp-card-root');
        if (!card) return;

        if (!statusData.configured) {
            renderSetupFlow(card, statusData);
        } else {
            renderVerifyFlow(card, statusData);
        }
    }

    function removeLoginModal() {
        currentRenderedMode = null;
        if (activeLoginModal && activeLoginModal.parentNode) {
            activeLoginModal.parentNode.removeChild(activeLoginModal);
            activeLoginModal = null;
        }
    }

    function renderSetupFlow(card, statusData) {
        card.innerHTML =
            '<h2 class="hmdm-auth-title">Set up Two-Factor Authentication</h2>' +
            '<p class="hmdm-auth-subtitle">Welcome <b>' + escapeHtml(statusData.name || statusData.username) + '</b>! To protect your account, two-factor authentication (TOTP) is required.</p>' +
            '<div id="hmdm-totp-alert" class="hmdm-totp-alert hmdm-totp-alert-danger"></div>' +
            '<div class="hmdm-qr-container">' +
            '<div class="hmdm-qr-code-box">' +
            '<div id="hmdm-totp-qr-loader" style="padding: 30px; font-size: 13px; color: #546e7a;">Generating secure QR code...</div>' +
            '<img id="hmdm-totp-qr-img" style="display:none;" alt="QR Code 2FA">' +
            '</div>' +
            '<div class="hmdm-secret-key-wrap" id="hmdm-totp-secret-box" style="display:none;">' +
            '<span>Manual key:</span>' +
            '<span class="hmdm-secret-code" id="hmdm-totp-secret-txt"></span>' +
            '<button type="button" class="hmdm-copy-secret-btn" id="hmdm-totp-copy-btn" title="Copy secret key">Copy</button>' +
            '</div>' +
            '</div>' +
            '<div class="hmdm-form-group">' +
            '<label class="hmdm-form-label" for="hmdm-totp-code-input">Code shown on Authenticator app:</label>' +
            '<input type="text" id="hmdm-totp-code-input" class="hmdm-form-input" maxlength="6" placeholder="e.g. 123456" autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]*">' +
            '</div>' +
            '<button type="button" id="hmdm-totp-submit-btn" class="hmdm-btn-submit">' +
            '<span>Verify and Enable 2FA</span>' +
            '</button>' +
            '<div id="hmdm-totp-backup-section" style="display:none;" class="hmdm-backup-box">' +
            '<div class="hmdm-backup-box-title">' +
            '<mat-icon role="img" class="mat-icon notranslate material-icons mat-ligature-font" style="font-size:16px;width:16px;height:16px;color:#546e7a;">vpn_key</mat-icon>' +
            '<span>Emergency Backup Codes</span>' +
            '</div>' +
            '<div>Save these codes in a safe place. You can use them to sign in if you lose access to your smartphone:</div>' +
            '<div class="hmdm-backup-grid" id="hmdm-totp-backup-list"></div>' +
            '</div>' +
            '<div class="hmdm-auth-footer-actions">' +
            '<a class="hmdm-auth-link hmdm-auth-link-secondary" id="hmdm-totp-logout-link">Cancel and Log Out</a>' +
            '</div>';

        fetch(API_BASE + '/setup', {
            method: 'GET',
            credentials: 'same-origin',
            headers: { 'Accept': 'application/json' }
        })
            .then(function (res) { return res.json(); })
            .then(function (resp) {
                if (resp && resp.status === 'OK' && resp.data) {
                    var d = resp.data;
                    var loader = document.getElementById('hmdm-totp-qr-loader');
                    if (loader) loader.style.display = 'none';

                    var img = document.getElementById('hmdm-totp-qr-img');
                    if (img) {
                        img.src = d.qrCode;
                        img.style.display = 'block';
                    }

                    var secTxt = document.getElementById('hmdm-totp-secret-txt');
                    var secBox = document.getElementById('hmdm-totp-secret-box');
                    if (secTxt && secBox) {
                        secTxt.textContent = d.secret;
                        secBox.style.display = 'flex';
                    }

                    if (d.backupCodes && d.backupCodes.length > 0) {
                        var bList = document.getElementById('hmdm-totp-backup-list');
                        if (bList) {
                            bList.innerHTML = '';
                            d.backupCodes.forEach(function (c) {
                                var item = document.createElement('div');
                                item.className = 'hmdm-backup-code-item';
                                item.textContent = c;
                                bList.appendChild(item);
                            });
                        }
                        var bSec = document.getElementById('hmdm-totp-backup-section');
                        if (bSec) bSec.style.display = 'block';
                    }

                    var copyBtn = document.getElementById('hmdm-totp-copy-btn');
                    if (copyBtn) {
                        copyBtn.onclick = function () {
                            navigator.clipboard.writeText(d.secret).then(function () {
                                copyBtn.textContent = 'Copied!';
                                setTimeout(function () { copyBtn.textContent = 'Copy'; }, 2000);
                            });
                        };
                    }

                    bindInputEvents();
                }
            })
            .catch(function () {
                showAlert('Unable to load 2FA setup data. Please try again later.', true);
            });
    }

    function renderVerifyFlow(card, statusData) {
        card.innerHTML =
            '<h2 class="hmdm-auth-title">Two-Factor Authentication</h2>' +
            '<p class="hmdm-auth-subtitle">Account: <b>' + escapeHtml(statusData.name || statusData.username) + '</b><br>Enter the temporary code generated by your Authenticator app.</p>' +
            '<div id="hmdm-totp-alert" class="hmdm-totp-alert hmdm-totp-alert-danger"></div>' +
            '<div class="hmdm-form-group">' +
            '<label class="hmdm-form-label" id="hmdm-totp-input-label" for="hmdm-totp-code-input">6-digit verification code</label>' +
            '<input type="text" id="hmdm-totp-code-input" class="hmdm-form-input" maxlength="6" placeholder="e.g. 123456" autocomplete="one-time-code" inputmode="numeric" autofocus>' +
            '</div>' +
            '<button type="button" id="hmdm-totp-submit-btn" class="hmdm-btn-submit">' +
            '<span>Verify and Sign In</span>' +
            '</button>' +
            '<div class="hmdm-auth-footer-actions">' +
            '<a class="hmdm-auth-link" id="hmdm-totp-backup-toggle">Lost your phone? Use a backup code</a>' +
            '<a class="hmdm-auth-link hmdm-auth-link-secondary" id="hmdm-totp-logout-link">Back to login</a>' +
            '</div>';

        bindInputEvents();
    }

    function bindInputEvents() {
        var input = document.getElementById('hmdm-totp-code-input');
        var submitBtn = document.getElementById('hmdm-totp-submit-btn');
        var logoutLink = document.getElementById('hmdm-totp-logout-link');
        var backupToggle = document.getElementById('hmdm-totp-backup-toggle');

        if (input) {
            input.focus();
            input.addEventListener('input', function () {
                var val = input.value.replace(/[^0-9]/g, '');
                input.value = val;
                if (val.length === 6 && input.maxLength === 6) {
                    doVerify(val);
                } else if (val.length === 8 && input.maxLength === 8) {
                    doVerify(val);
                }
            });
            input.addEventListener('keydown', function (e) {
                if (e.key === 'Enter') {
                    doVerify(input.value);
                }
            });
        }

        if (submitBtn) {
            submitBtn.onclick = function () {
                if (input) doVerify(input.value);
            };
        }

        if (logoutLink) {
            logoutLink.onclick = function () {
                fetch('/rest/public/auth/logout', { method: 'POST', credentials: 'same-origin' })
                    .finally(function () {
                        removeLoginModal();
                        sessionStorage.removeItem('hmdm_2fa_ok');
                        window.location.reload();
                    });
            };
        }

        if (backupToggle) {
            backupToggle.onclick = function () {
                var label = document.getElementById('hmdm-totp-input-label');
                if (label) label.textContent = '8-digit backup code';
                if (input) {
                    input.maxLength = 8;
                    input.placeholder = 'e.g. 12345678';
                    input.value = '';
                    input.focus();
                }
                backupToggle.style.display = 'none';
            };
        }
    }

    function doVerify(code) {
        if (!code || code.trim().length < 6) {
            showAlert('Please enter the full code.', true);
            return;
        }

        var btn = document.getElementById('hmdm-totp-submit-btn');
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = '<span>Verifying...</span>';
        }

        var payload = (code.length === 8) ? { backupCode: code } : { code: code };

        fetch(API_BASE + '/verify', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify(payload)
        })
            .then(function (res) { return res.json(); })
            .then(function (resp) {
                if (resp && resp.status === 'OK') {
                    sessionStorage.removeItem('hmdm_2fa_pending');
                    sessionStorage.setItem('hmdm_2fa_verified', '1');
                    showAlert('Verification successful! Signing in...', false);
                    setTimeout(function () {
                        removeLoginModal();
                        isVerified = true;
                    }, 400);
                } else {
                    showAlert(resp.message || 'Invalid code. Please try again.', true);
                    if (btn) {
                        btn.disabled = false;
                        btn.innerHTML = '<span>Verify and Sign In</span>';
                    }
                    var input = document.getElementById('hmdm-totp-code-input');
                    if (input) {
                        input.value = '';
                        input.focus();
                    }
                }
            })
            .catch(function () {
                showAlert('Server communication error.', true);
                if (btn) {
                    btn.disabled = false;
                    btn.innerHTML = '<span>Verify and Sign In</span>';
                }
            });
    }

    function showAlert(msg, isError) {
        var alert = document.getElementById('hmdm-totp-alert');
        if (!alert) return;
        alert.textContent = msg;
        alert.className = 'hmdm-totp-alert ' + (isError ? 'hmdm-totp-alert-danger' : 'hmdm-totp-alert-success');
        alert.style.display = 'block';
    }

    function escapeHtml(str) {
        if (!str) return '';
        return str.replace(/[&<>'"]/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[c];
        });
    }

    // -------------------------------------------------------------
    // 6. NETWORK & NAVIGATION HOOKS (Immediate 0ms Detection)
    // -------------------------------------------------------------
    function isLoginUrl(url) {
        return url && (url.indexOf('auth/login') !== -1 || url.indexOf('rest/public/auth/login') !== -1);
    }

    function isLogoutUrl(url) {
        return url && (url.indexOf('auth/logout') !== -1 || url.indexOf('rest/public/auth/logout') !== -1);
    }

    function isPrivateApi(url) {
        return url && (url.indexOf('rest/private/') !== -1 || url.indexOf('users/current') !== -1);
    }

    function hookNetworkCalls() {
        var origOpen = XMLHttpRequest.prototype.open;
        var origSend = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.open = function (method, url) {
            this._hmdmUrl = url;
            return origOpen.apply(this, arguments);
        };
        XMLHttpRequest.prototype.send = function () {
            var self = this;
            this.addEventListener('load', function () {
                if (self._hmdmUrl) {
                    if (isLoginUrl(self._hmdmUrl) && self.status === 200) {
                        sessionStorage.setItem('hmdm_2fa_pending', '1');
                        showPreGate();
                        checkTotpStatus();
                    } else if (isLogoutUrl(self._hmdmUrl)) {
                        sessionStorage.removeItem('hmdm_2fa_pending');
                        sessionStorage.removeItem('hmdm_2fa_verified');
                        removeLoginModal();
                        removeSidebarMenuItem();
                        isVerified = false;
                    } else if (!isVerified && isPrivateApi(self._hmdmUrl)) {
                        checkTotpStatus();
                    }
                }
            });
            return origSend.apply(this, arguments);
        };

        if (window.fetch) {
            var origFetch = window.fetch;
            window.fetch = function (input, init) {
                var url = (typeof input === 'string') ? input : (input && input.url ? input.url : '');
                return origFetch.apply(this, arguments).then(function (res) {
                    if (url) {
                        if (isLoginUrl(url) && res.status === 200) {
                            sessionStorage.setItem('hmdm_2fa_pending', '1');
                            showPreGate();
                            checkTotpStatus();
                        } else if (isLogoutUrl(url)) {
                            sessionStorage.removeItem('hmdm_2fa_pending');
                            sessionStorage.removeItem('hmdm_2fa_verified');
                            removeLoginModal();
                            removeSidebarMenuItem();
                            isVerified = false;
                        } else if (!isVerified && isPrivateApi(url)) {
                            checkTotpStatus();
                        }
                    }
                    return res;
                });
            };
        }

        // Hook client-side navigation in Angular SPA (Immediate 0ms route detection)
        var origPushState = history.pushState;
        history.pushState = function () {
            var ret = origPushState.apply(this, arguments);
            if (!isVerified) {
                checkTotpStatus();
            }
            return ret;
        };

        var origReplaceState = history.replaceState;
        history.replaceState = function () {
            var ret = origReplaceState.apply(this, arguments);
            if (!isVerified) {
                checkTotpStatus();
            }
            return ret;
        };

        window.addEventListener('popstate', function () {
            if (!isVerified) {
                checkTotpStatus();
            }
        });
    }

    // -------------------------------------------------------------
    // 7. INITIALIZATION & MUTATION OBSERVER
    // -------------------------------------------------------------
    function init() {
        ensureStyles();

        // If 2FA was pending across a page reload or fresh visit, show gate immediately
        if (sessionStorage.getItem('hmdm_2fa_pending') === '1') {
            showPreGate();
        }

        hookNetworkCalls();
        checkTotpStatus();

        var observer = new MutationObserver(function () {
            if (currentUserData && currentUserData.isAdmin) {
                injectSidebarMenuItem();
            } else {
                removeSidebarMenuItem();
            }
        });

        if (document.body) {
            observer.observe(document.body, { childList: true, subtree: true });
        }

        // Instant update when sidebar accordion or nodes are clicked
        document.addEventListener('click', function () {
            setTimeout(function () {
                if (currentUserData && currentUserData.isAdmin) {
                    injectSidebarMenuItem();
                } else {
                    removeSidebarMenuItem();
                }
            }, 60);
        }, true);

        // Check status periodically ONLY if 2FA modal is NOT currently open on screen
        setInterval(function () {
            if (!isVerified && !activeLoginModal) {
                checkTotpStatus();
            }
        }, 5000);

        // Standard poll once 2FA has been verified
        setInterval(function () {
            if (isVerified) {
                checkTotpStatus();
            }
        }, 15000);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();
