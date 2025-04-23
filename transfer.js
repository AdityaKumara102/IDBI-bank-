document.addEventListener('DOMContentLoaded', function() {

    // --- Form Handling (Keep existing logic) ---
    const loginForm = document.getElementById('loginForm');
    const signupForm = document.getElementById('signupForm');

    if (loginForm) {
        loginForm.addEventListener('submit', function(event) {
            event.preventDefault();
            console.log('Login form submitted (prevented default)');
            // Replace alert with a more subtle notification in a real app
            alert('Login functionality would connect to a backend here.');
        });
    }

    if (signupForm) {
        signupForm.addEventListener('submit', function(event) {
            event.preventDefault();
            const initialDepositInput = document.getElementById('initialDeposit');
            const initialDeposit = initialDepositInput ? parseFloat(initialDepositInput.value) : 0;
            const minDeposit = initialDepositInput ? parseFloat(initialDepositInput.min) : 1000;

            if (initialDeposit < minDeposit) {
                alert(`Initial deposit must be at least ₹${minDeposit}.`);
                if(initialDepositInput) initialDepositInput.focus();
            } else {
                console.log('Signup form submitted (prevented default)');
                 // Replace alert with a more subtle notification
                alert('Account creation request would be sent to a backend here.');
                // signupForm.reset(); // Optionally clear form
            }
        });
    }

    // --- Update Footer Year ---
    const currentYearSpan = document.getElementById('currentYear');
    if (currentYearSpan) {
        currentYearSpan.textContent = new Date().getFullYear();
    }

    // --- Smooth Scroll for Nav Links (Keep existing logic) ---
    const navLinks = document.querySelectorAll('header nav a[href^="#"]');
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const targetId = this.getAttribute('href');
            const targetElement = document.querySelector(targetId);
            if (targetElement) {
                 // Calculate offset for fixed header (adjust if header height changes)
                 const headerOffset = 80;
                 const elementPosition = targetElement.getBoundingClientRect().top;
                 const offsetPosition = elementPosition + window.pageYOffset - headerOffset;

                 window.scrollTo({
                     top: offsetPosition,
                     behavior: 'smooth'
                 });
            }
        });
    });

    // --- Intersection Observer for Card Animations ---
    const animatedCards = document.querySelectorAll('.animated-card');

    if ('IntersectionObserver' in window) { // Check if browser supports it
        const cardObserver = new IntersectionObserver((entries, observer) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('visible');
                    observer.unobserve(entry.target); // Stop observing once visible
                }
            });
        }, {
            rootMargin: '0px 0px -100px 0px' // Trigger when element is 100px into view
           // threshold: 0.1 // Or trigger when 10% is visible
        });

        animatedCards.forEach(card => {
            cardObserver.observe(card);
        });
    } else {
        // Fallback for older browsers: make cards visible immediately
        animatedCards.forEach(card => {
            card.classList.add('visible');
        });
    }

});