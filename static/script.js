// This file will contain JavaScript for frontend interactions.

// Debounce function to limit how often a function is called
function debounce(func, delay) {
    let timeout;
    return function(...args) {
        const context = this;
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(context, args), delay);
    };
}

document.addEventListener('DOMContentLoaded', function() {
    // Correctly reference the Google Sheet elements
    const googleSheetSelect = document.getElementById('googleSheetSelect');
    const sheetSearchInput = document.getElementById('sheetSearchInput');
    const sheetDataPreview = document.getElementById('sheet-data-preview');
    const newBulkMessageBtn = document.getElementById('new-bulk-message-btn');
    const bulkMessageComposer = document.querySelector('.bulk-message-composer');
    const bulkMessageTemplate = document.getElementById('bulk-message-template');
    const sendBulkSmsBtn = document.getElementById('send-bulk-sms-btn');

    // Conversation elements
    const conversationList = document.querySelector('.conversation-list');
    const conversationSearch = document.getElementById('conversation-search');
    const newConversationBtn = document.getElementById('new-conversation-btn');
    const conversationDisplay = document.querySelector('.conversation-display');
    const newMessageInput = document.getElementById('new-message');
    const sendMessageBtn = document.getElementById('send-message-btn');

    let currentConversationId = null;
    let currentConversationRoom = null; // To track the current conversation room
    let currentUserRoom = null; // To track the current user's room

    // Socket.IO setup
    const socket = io();

    socket.on('connect', () => {
        console.log('Socket.IO connected!');
        if (currentUserId) {
            currentUserRoom = String(currentUserId);
            socket.emit('join', { 'room': currentUserRoom });
            console.log(`Joined user room: ${currentUserRoom}`);
        }
        fetchConversations();
    });

    socket.on('disconnect', () => {
        console.log('Socket.IO disconnected.');
        if (currentUserRoom) {
            socket.emit('leave', { 'room': currentUserRoom }); // Leave user room on disconnect
            console.log(`Left user room: ${currentUserRoom}`);
        }
    });

    socket.on('new_message', (data) => {
        console.log('Socket.IO: New message received:', data);
        if (data.conversation_id == currentConversationId) {
            const messageDiv = document.createElement('div');
            messageDiv.classList.add('message', data.sender === 'user' ? 'sent' : 'received');
            messageDiv.innerHTML = `<p>${data.body}</p><span class="timestamp">${new Date(data.timestamp).toLocaleString()}</span>`;
            conversationDisplay.appendChild(messageDiv);
            conversationDisplay.scrollTop = conversationDisplay.scrollHeight;
        }
        fetchConversations(); // Refresh conversations list to update unread counts and last message
    });

    socket.on('conversation_update', (data) => {
        console.log('Socket.IO: Conversation update received:', data);
        // This event signifies that the conversation list in the left pane might need updating
        fetchConversations();
    });

    // Function to fetch and populate Google Sheets
    async function fetchGoogleSheets(searchQuery = '') {
        console.log("Fetching Google Sheets...");
        try {
            const url = searchQuery ? `/google_sheets?search=${encodeURIComponent(searchQuery)}` : '/google_sheets';
            const response = await fetch(url);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const sheets = await response.json();
            console.log("Sheets fetched:", sheets);
            googleSheetSelect.innerHTML = '<option value="">Select a Google Sheet</option>';
            sheets.forEach(sheet => {
                const option = document.createElement('option');
                option.value = sheet.id;
                option.textContent = sheet.name;
                googleSheetSelect.appendChild(option);
            });
        } catch (error) {
            console.error("Error fetching Google Sheets:", error);
            sheetDataPreview.innerHTML = '<p style="color: red;">Error loading sheets.</p>';
        }
    }

    // Function to fetch and display sheet data
    async function fetchSheetData(sheetId) {
        if (!sheetId) {
            sheetDataPreview.innerHTML = '<p>Select a sheet to see its preview.</p>';
            return;
        }

        try {
            const response = await fetch(`/google_sheet_data/${sheetId}`);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const data = await response.json();

            if (data.error) {
                sheetDataPreview.innerHTML = `<p style="color: red;">${data.error}</p>`;
                return;
            }

            let html = '<table><thead><tr>';
            data.headers.forEach(header => {
                html += `<th>${header}</th>`;
            });
            html += '</tr></thead><tbody>';

            data.data.forEach(row => {
                html += '<tr>';
                row.forEach(cell => {
                    html += `<td>${cell}</td>`;
                });
                html += '</tr>';
            });
            html += '</tbody></table>';
            sheetDataPreview.innerHTML = html;

            // Store headers globally or make them accessible for templating
            window.currentSheetHeaders = data.headers;
            console.log('Available headers for templating:', window.currentSheetHeaders);

        } catch (error) {
            console.error('Error fetching sheet data:', error);
            sheetDataPreview.innerHTML = '<p style="color: red;">Error loading sheet data.</p>';
        }
    }

    // Function to fetch and display conversations
    async function fetchConversations() {
        try {
            const response = await fetch('/api/conversations');
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const conversations = await response.json();
            conversationList.innerHTML = ''; // Clear existing list
            conversations.forEach(conv => {
                const convItem = document.createElement('div');
                convItem.classList.add('conversation-item');
                if (conv.id === currentConversationId) {
                    convItem.classList.add('active');
                }
                convItem.dataset.conversationId = conv.id;
                
                const timeDisplay = conv.last_message_time ? new Date(conv.last_message_time).toLocaleString() : '';
                const unreadDot = conv.unread_count > 0 ? '<span class="unread-dot"></span>' : '';
                const unreadCountDisplay = conv.unread_count > 0 ? `<span class="unread-count">${conv.unread_count}</span>` : '';

                convItem.innerHTML = `
                    <div class="conversation-info">
                        <div class="contact-name">${conv.contact_name}</div>
                        <div class="last-message-preview">${conv.last_message_body || 'No messages yet.'}</div>
                    </div>
                    <div class="conversation-meta">
                        <div class="last-message-time">${timeDisplay}</div>
                        ${unreadDot}
                        ${unreadCountDisplay}
                    </div>
                `;
                convItem.addEventListener('click', () => {
                    selectConversation(conv.id);
                });
                conversationList.appendChild(convItem);
            });
        } catch (error) {
            console.error('Error fetching conversations:', error);
            conversationList.innerHTML = '<p style="color: red;">Error loading conversations.</p>';
        }
    }

    // Function to fetch and display messages for the current conversation
    async function fetchMessagesForCurrentConversation() {
        if (!currentConversationId) return;

        try {
            const response = await fetch(`/api/conversations/${currentConversationId}/messages`);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const data = await response.json();
            conversationDisplay.innerHTML = ''; 
            data.messages.forEach(msg => {
                const messageDiv = document.createElement('div');
                messageDiv.classList.add('message', msg.sender === 'user' ? 'sent' : 'received');
                messageDiv.innerHTML = `<p>${msg.body}</p><span class="timestamp">${new Date(msg.timestamp).toLocaleString()}</span>`;
                conversationDisplay.appendChild(messageDiv);
            });
            conversationDisplay.scrollTop = conversationDisplay.scrollHeight; // Scroll to bottom

        } catch (error) {
            console.error('Error fetching messages for current conversation:', error);
            conversationDisplay.innerHTML = '<p style="color: red;">Error loading messages.</p>';
        }
    }

    // Function to select a conversation and load its messages
    async function selectConversation(convId) {
        if (currentConversationRoom && currentConversationRoom !== String(convId)) {
            socket.emit('leave', { 'room': currentConversationRoom });
            console.log(`Left conversation room: ${currentConversationRoom}`);
        }

        currentConversationId = convId;
        currentConversationRoom = String(convId);
        socket.emit('join', { 'room': currentConversationRoom });
        console.log(`Joined conversation room: ${currentConversationRoom}`);

        // Highlight selected conversation
        document.querySelectorAll('.conversation-item').forEach(item => {
            item.classList.remove('active');
        });
        document.querySelector(`.conversation-item[data-conversation-id="${convId}"]`).classList.add('active');

        // Call API to mark conversation as read
        try {
            const response = await fetch(`/api/conversations/${convId}/mark_read`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
            });
            if (!response.ok) {
                console.error('Failed to mark conversation as read.', await response.json());
            } else {
                // Only after marking as read successfully, then fetch messages and refresh conversation list
                fetchMessagesForCurrentConversation(); // Initial load
                fetchConversations(); // Refresh conversations list to clear unread count
            }
        } catch (error) {
            console.error('Error marking conversation as read:', error);
        }
    }

    // Event Listeners
    if (googleSheetSelect) {
        googleSheetSelect.addEventListener('change', function() {
            fetchSheetData(this.value);
        });
    }

    if (sheetSearchInput) {
        sheetSearchInput.addEventListener('input', debounce(function() {
            const query = sheetSearchInput.value;
            fetchGoogleSheets(query);
        }, 300)); // Debounce to avoid excessive API calls
    }

    newBulkMessageBtn.addEventListener('click', function() {
        bulkMessageComposer.style.display = 'block';
    });

    sendBulkSmsBtn.addEventListener('click', async function() {
        const sheetId = googleSheetSelect.value;
        const messageTemplate = bulkMessageTemplate.value;

        if (!sheetId) {
            alert('Please select a Google Sheet first.');
            return;
        }

        if (!messageTemplate) {
            alert('Please enter a message template.');
            return;
        }

        try {
            const response = await fetch('/send_templated_bulk_sms', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ sheet_id: sheetId, message_template: messageTemplate }),
            });

            const result = await response.json();
            if (response.ok) {
                alert('Bulk SMS sent successfully!\n' + result.results.join('\n'));
                fetchConversations(); // Refresh conversations list after sending bulk message
            } else {
                alert('Error sending bulk SMS: ' + result.error);
            }
        } catch (error) {
            console.error('Error sending bulk SMS:', error);
            alert('An error occurred while sending bulk SMS.');
        }
    });

    newConversationBtn.addEventListener('click', async function() {
        const phoneNumbers = prompt("Enter phone numbers (comma-separated): ");
        if (phoneNumbers) {
            const contactName = prompt("Enter a contact name (optional): ");
            const initialMessage = prompt("Enter an optional initial message: ");
            try {
                const response = await fetch('/api/start_conversation', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ phone_numbers: phoneNumbers, initial_message: initialMessage, contact_name: contactName }),
                });
                const result = await response.json();
                if (response.ok) {
                    alert(result.message);
                    fetchConversations(); // Refresh conversations list
                } else {
                    alert('Error starting conversation: ' + result.error);
                }
            } catch (error) {
                console.error('Error starting conversation:', error);
                alert('An error occurred while starting conversation.');
            }
        }
    });

    sendMessageBtn.addEventListener('click', async function() {
        sendMessage();
    });

    newMessageInput.addEventListener('keydown', function(event) {
        if (event.key === 'Enter' && !event.shiftKey) {
            event.preventDefault(); // Prevent default form submission
            sendMessage();
        }
    });

    // Helper function to send message
    async function sendMessage() {
        const messageBody = newMessageInput.value;
        if (!currentConversationId) {
            alert('Please select a conversation first.');
            return;
        }
        if (!messageBody) {
            alert('Message cannot be empty.');
            return;
        }

        try {
            const response = await fetch(`/api/send_message/${currentConversationId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ message: messageBody }),
            });

            const result = await response.json();
            if (response.ok) {
                newMessageInput.value = '';
            } else {
                alert('Error sending message: ' + result.error);
            }
        } catch (error) {
            console.error('Error sending message:', error);
            alert('An error occurred while sending message.');
        }
    }

    conversationSearch.addEventListener('keyup', function() {
        const searchTerm = this.value.toLowerCase();
        document.querySelectorAll('.conversation-item').forEach(item => {
            const contactName = item.querySelector('.contact-name').textContent.toLowerCase();
            const lastMessage = item.querySelector('.last-message-preview').textContent.toLowerCase();
            if (contactName.includes(searchTerm) || lastMessage.includes(searchTerm)) {
                item.style.display = '';
            } else {
                item.style.display = 'none';
            }
        });
    });

    // Initial fetches when the page loads
    fetchGoogleSheets();
    fetchConversations();

    // Twilio Settings Form submission
    // const twilioSettingsForm = document.getElementById('twilio-settings-form');
    // const twilioFeedback = document.getElementById('twilio-feedback');

    // if (twilioSettingsForm) {
    //     twilioSettingsForm.addEventListener('submit', async function(event) {
    //         event.preventDefault();
    //         twilioFeedback.textContent = ''; // Clear previous messages
    //         twilioFeedback.style.color = 'black';
    //         twilioFeedback.textContent = 'Saving...';

    //         const accountSid = document.getElementById('account_sid').value;
    //         const authToken = document.getElementById('auth_token').value;
    //         const phoneNumber = document.getElementById('phone_number').value;

    //         try {
    //             const response = await fetch('/api/configure_twilio', {
    //                 method: 'POST',
    //                 headers: {
    //                     'Content-Type': 'application/json',
    //                 },
    //                 body: JSON.stringify({ account_sid: accountSid, auth_token: authToken, phone_number: phoneNumber }),
    //             });

    //             const result = await response.json();
    //             if (response.ok) {
    //                 twilioFeedback.style.color = 'green';
    //                 twilioFeedback.textContent = result.message;
    //             } else {
    //                 twilioFeedback.style.color = 'red';
    //                 twilioFeedback.textContent = result.error;
    //             }
    //         } catch (error) {
    //             console.error('Error saving Twilio settings:', error);
    //             twilioFeedback.style.color = 'red';
    //             twilioFeedback.textContent = 'An unexpected error occurred.';
    //         }
    //     });
    // }
});
