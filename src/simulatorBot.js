const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({ headless: false });
  
  // Function to introduce a delay
  const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

  for (let i = 0; i < 200; i++) {
    const page = await browser.newPage();

    // Go to the Auth0 authorization URL
    await page.goto('https://dev-q7ybk7ocujetu4ff.ca.auth0.com/authorize?client_id=N6fJ5OXJhRh7CqFw1HxOccIBZS543jHu&scope=openid%20profile%20email%20offline_access&redirect_uri=http://localhost:5174&response_type=code&response_mode=query&state=Qkxpei5IZ3h1a2hWNENCNkFkT2ZseEx2STNBeFM4ZFZBR0xvOXN6N2lHVg==&nonce=fjc3RFVsVkdGM3QyZ3F6WG45MmY0b2wyeGU2RFZQN2drNU5SSmJmS0RPWA==&code_challenge=A-JIAogVbQLtiuriNfgV6I8l6W7a3H5Kqzl6d2N8I_Q&code_challenge_method=S256&auth0Client=eyJuYW1lIjoiYXV0aDAtcmVhY3QiLCJ2ZXJzaW9uIjoiMi4wLjEifQ==');

    // Wait for the login form to load
    await page.waitForSelector('input[name="username"]');
    
    // Enter credentials
  // Enter credentials
  await page.type('input[name="username"]', 'ysharat1@yopmail.com'); // Replace with your username
  await page.type('input[name="password"]', 'Welcome@123'); // Replace with your password
    
    // Submit the form
    await page.click('button[type="submit"]');
    
    // Wait for the MFA challenge (if prompted)
    await page.waitForNavigation();
    
    // Simulate solving MFA (approve push manually)
    
    // Wait for the redirect (after MFA)
    console.log(`Login ${i + 1} complete, redirected to: `, page.url());
    
    // Clear cookies to ensure a fresh session for each request
    await page.deleteCookie(...(await page.cookies()));

    // Close the page
    await page.close();

    // Add delay to avoid rate limiting
    await delay(3000); // Wait 10 seconds before the next iteration
  }

  await browser.close();
})();
