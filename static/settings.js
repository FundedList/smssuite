document.addEventListener('DOMContentLoaded', function() {
    const twilioSettingsForm = document.getElementById('twilio-settings-form');
    const twilioFeedback = document.getElementById('twilio-feedback');

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
});
