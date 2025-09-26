function debounce(func, delay) {
    let timeout;
    return function(...args) {
        const context = this;
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(context, args), delay);
    };
}

document.addEventListener('DOMContentLoaded', function() {
    const twilioSettingsForm = document.getElementById('twilio-settings-form');
    const twilioFeedback = document.getElementById('twilio-feedback');
    const importTwilioHistoryBtn = document.getElementById('import-twilio-history-btn');
    const importHistoryFeedback = document.getElementById('import-history-feedback');

    if (twilioSettingsForm) {
        twilioSettingsForm.addEventListener('submit', async function(event) {
            event.preventDefault();
            twilioFeedback.textContent = ''; // Clear previous messages
            twilioFeedback.style.color = 'black';
            twilioFeedback.textContent = 'Saving...';

            const accountSid = document.getElementById('account_sid').value;
            const authToken = document.getElementById('auth_token').value;
            const phoneNumber = document.getElementById('phone_number').value;

            try {
                const response = await fetch('/api/configure_twilio', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ account_sid: accountSid, auth_token: authToken, phone_number: phoneNumber }),
                });

                const result = await response.json();
                if (response.ok) {
                    twilioFeedback.style.color = 'green';
                    twilioFeedback.textContent = result.message;
                    // Optionally, trigger a refresh of other parts of the UI if needed
                } else {
                    twilioFeedback.style.color = 'red';
                    twilioFeedback.textContent = result.error;
                }
            } catch (error) {
                console.error('Error saving Twilio settings:', error);
                twilioFeedback.style.color = 'red';
                twilioFeedback.textContent = 'An unexpected error occurred.';
            }
        });
    }

    if (importTwilioHistoryBtn) {
        importTwilioHistoryBtn.addEventListener('click', async function() {
            if (!confirm("Importing historical data may take a while and could potentially create new conversations. Do you want to proceed?")) {
                return;
            }
            importHistoryFeedback.textContent = '';
            importHistoryFeedback.style.color = 'black';
            importHistoryFeedback.textContent = 'Importing... This may take a while.';
            
            try {
                const response = await fetch('/api/import_twilio_history', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                });
                const result = await response.json();
                if (response.ok) {
                    importHistoryFeedback.style.color = 'green';
                    importHistoryFeedback.textContent = result.message;
                } else {
                    importHistoryFeedback.style.color = 'red';
                    importHistoryFeedback.textContent = result.error;
                }
            } catch (error) {
                console.error('Error importing Twilio history:', error);
                importHistoryFeedback.style.color = 'red';
                importHistoryFeedback.textContent = 'An unexpected error occurred during import.';
            }
        });
    }
});
