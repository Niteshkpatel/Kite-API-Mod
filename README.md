
---

# Kite Connect API Wrapper

This Python module provides a convenient wrapper for the Kite Connect trading and investment platform's API. It allows easy access to various functionalities like fetching user profiles, placing and modifying orders, retrieving market data, and much more.

## Installation

Before you begin, ensure you have Python installed on your system. This module has dependencies on modules like `requests`, `json`, `pyotp`, and `dateutil`, which need to be installed if not already available.

You can clone this repository or download the source code to your local machine. If the module is part of a larger package, follow the specific installation instructions for that package.

## Setup

To use this module, first, you need to import it into your Python script. Ensure the module file is in your Python path.

```python
import Z_KiteConnect
```

## Initialization

To start using the Kite Connect API, you need to create an instance of the `KiteConnect` class. You'll need to provide your user ID, password, and a secret key for OTP generation.

```python
kite = Z_KiteConnect.KiteConnect(user_id="your_user_id", password="your_password", otp_secret_key="your_otp_secret")
```

Replace `"your_user_id"`, `"your_password"`, and `"your_otp_secret"` with your actual Kite Connect credentials and OTP secret key. OTP secret key is the 25 characters key that you get from the 2FA authentication.

## Usage

Here are some examples of how you can use the class and its methods:

### Fetching User Profile

To get the user profile details, use:

```python
profile = kite.profile()
print(profile)
```

### Placing an Order

To place a trading order, you can use:

```python
order_id = kite.place_order(variety="regular", exchange="NSE", tradingsymbol="INFY",
                            transaction_type="BUY", quantity=1, product="CNC",
                            order_type="LIMIT", price=1000)
print("Order placed with ID:", order_id)
```

### Fetching Order History

To get the history of a specific order, use:

```python
order_history = kite.order_history(order_id="your_order_id")
print(order_history)
```

Replace `"your_order_id"` with the actual ID of the order you want to fetch history for.


## Contribution

Contributions to this module are welcome. Please ensure you follow the coding conventions and write unit tests for any new feature or fix.


## Contact


In case of any queries, Contact me @ https://www.linkedin.com/in/toniteshpatel/

---

