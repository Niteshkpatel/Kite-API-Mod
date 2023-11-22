#!/usr/bin/env python
# coding: utf-8


from six import StringIO, PY2
from six.moves.urllib.parse import urljoin
import csv
import json
import dateutil.parser
import hashlib
import logging
import datetime
import requests
import pyotp
import exceptions as ex
import options_name


# ## Download and write instruments token to a file


def get_instrument():
    instrument_token_url = 'https://api.kite.trade/instruments'
    instrument_token = requests.get(instrument_token_url, allow_redirects=True)
    
    open('instruments.csv', 'wb').write(instrument_token.content)

# Setting up logging

log = logging.getLogger(__name__)

# Kite Connect API wrapper class

class KiteConnect(object):
    """
    The Kite Connect API wrapper class.

    In production, you may initialise a single instance of this class per `api_key`.
    """

    # Default root API endpoint. It's possible to
    # override this by passing the `root` parameter during initialisation.
    _default_root_uri = "https://kite.zerodha.com/oms"
#     _default_root_uri = "https://api.kite.trade"
#     _default_login_uri = "https://kite.trade/connect/login"
    _default_timeout = 7  # In seconds

    # Constants
    # Products
    PRODUCT_MIS = "MIS"
    PRODUCT_CNC = "CNC"
    PRODUCT_NRML = "NRML"
    PRODUCT_CO = "CO"
    PRODUCT_BO = "BO"

    # Order types
    ORDER_TYPE_MARKET = "MARKET"
    ORDER_TYPE_LIMIT = "LIMIT"
    ORDER_TYPE_SLM = "SL-M"
    ORDER_TYPE_SL = "SL"

    # Varities
    VARIETY_REGULAR = "regular"
    VARIETY_BO = "bo"
    VARIETY_CO = "co"
    VARIETY_AMO = "amo"

    # Transaction type
    TRANSACTION_TYPE_BUY = "BUY"
    TRANSACTION_TYPE_SELL = "SELL"

    # Validity
    VALIDITY_DAY = "DAY"
    VALIDITY_IOC = "IOC"

    # Position Type
    POSITION_TYPE_DAY = "day"
    POSITION_TYPE_OVERNIGHT = "overnight"

    # Exchanges
    EXCHANGE_NSE = "NSE"
    EXCHANGE_BSE = "BSE"
    EXCHANGE_NFO = "NFO"
    EXCHANGE_CDS = "CDS"
    EXCHANGE_BFO = "BFO"
    EXCHANGE_MCX = "MCX"

    # Margins segments
    MARGIN_EQUITY = "equity"
    MARGIN_COMMODITY = "commodity"

    # Status constants
    STATUS_COMPLETE = "COMPLETE"
    STATUS_REJECTED = "REJECTED"
    STATUS_CANCELLED = "CANCELLED"

    # GTT order type
    GTT_TYPE_OCO = "two-leg"
    GTT_TYPE_SINGLE = "single"

    # GTT order status
    GTT_STATUS_ACTIVE = "active"
    GTT_STATUS_TRIGGERED = "triggered"
    GTT_STATUS_DISABLED = "disabled"
    GTT_STATUS_EXPIRED = "expired"
    GTT_STATUS_CANCELLED = "cancelled"
    GTT_STATUS_REJECTED = "rejected"
    GTT_STATUS_DELETED = "deleted"
    
    
    # URIs to various calls
    _routes = {
        "api.token": "/session/token",
        "api.token.invalidate": "/session/token",
        "api.token.renew": "/session/refresh_token",
        "user.profile": "/oms/user/profile",
        "user.margins": "/oms/user/margins",
        "user.margins.segment": "/oms/user/margins/{segment}",

        "orders": "/oms/orders",
        "trades": "/oms/trades",

        "order.info": "/oms/orders/{order_id}",
        "order.place": "/oms/orders/{variety}",
        "order.modify": "/oms/orders/{variety}/{order_id}",
        "order.cancel": "/oms/orders/{variety}/{order_id}",
        "order.trades": "/oms/orders/{order_id}/trades",

        "portfolio.positions": "/oms/portfolio/positions",
        "portfolio.holdings": "/oms/portfolio/holdings",
        "portfolio.positions.convert": "/oms/portfolio/positions",

        # Margin computation endpoints
        "order.margins": "/oms/margins/orders",
        "order.margins.basket": "/oms/margins/basket",
        
        "market.instruments.all": "/oms/instruments",
        "market.instruments": "/oms/instruments/{exchange}",
        "market.margins": "/oms/margins/{segment}",
        "market.historical": "/oms/instruments/historical/{instrument_token}/{interval}",
        "market.trigger_range": "/oms/instruments/trigger_range/{transaction_type}",

        "market.quote": "/oms/quote",
        "market.quote.ohlc": "/oms/quote/ohlc",
        "market.quote.ltp": "/oms/quote/ltp"
    }

    def __init__(self,user_id,password,otp_secret_key,root="https://kite.zerodha.com/oms",
                 debug=False,
                 timeout=None,
                 proxies=None,
                 pool=None,
                 disable_ssl=False):
        self.user_id = user_id
        self.totp = otp_secret_key
        self.init_headers = {
            'authority': 'kite.zerodha.com',
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'en-GB,en;q=0.9',
            # Requests sorts cookies= alphabetically
            # 'cookie': 'kf_session=0nkSm8JunenGWsw2vtn3XOWeyREv9lhe; _cfuvid=kz1riv8DfJYZwvjt1tE8HVgMEZ.fUmYxbrhJs.xOGVA-1669054076903-0-604800000',
            'dnt': '1',
            'origin': 'https://kite.zerodha.com',
            'referer': 'https://kite.zerodha.com/',
            'sec-ch-ua': '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36',
            'x-kite-app-uuid': 'f6a994b1-331d-4c4d-a623-addf02c5e532',
            'x-kite-userid': self.user_id,
            'x-kite-version': '3.0.7',
        }
        self._header_dict1 = {
            'Connection': 'keep-alive',
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache',
            'X-Kite-Version': '3.0.7',
            'Accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Kite-Userid': self.user_id,
            'sec-ch-ua-mobile': '?0',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36',
            'sec-ch-ua': '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
            'Origin': 'https://kite.zerodha.com',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Dest': 'empty',
            'Referer': 'https://kite.zerodha.com/',
            'Accept-Language': 'en-US,en;q=0.9',
        }
        self._header_dict2 = {
            'Connection': 'keep-alive',
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache',
            'Upgrade-Insecure-Requests': '1',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'sec-ch-ua': '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'Referer': 'https://kite.zerodha.com/',
            'Accept-Language': 'en-US,en;q=0.9',
        }

        self.cookies_data = {
        }
        
        self.debug = debug
        self.session_expiry_hook = None
        self.disable_ssl = disable_ssl
        self.proxies = proxies if proxies else {}

        self.root =  root 
        self.timeout = timeout or self._default_timeout

        # Initialize HTTP session
        # Create requests session only if pool exists. Reuse session
        # for every request. Otherwise create session for each request
#         if pool:
        self.reqsession = requests.Session()

        # disable requests SSL warning
        requests.packages.urllib3.disable_warnings()
        
        login_request = {
            'user_id': self.user_id,
            'password': password
        }
        login_response = self.reqsession.post("https://kite.zerodha.com/api/login",login_request,headers=self.init_headers)
        self.cookies_data.update(login_response.cookies.get_dict())
        print("Req Id:",json.loads(login_response.text))
        self.cookies_data.update({'request_id':json.loads(login_response.text)['data']['request_id']})
        totp = pyotp.TOTP(self.totp)
        data = {
          'user_id': self.user_id,
          'request_id': self.cookies_data['request_id'],
          'twofa_value': totp.now(),
          'twofa_type' : 'totp',
          'skip_session': ''
        }
        login_response = self.reqsession.post('https://kite.zerodha.com/api/twofa', headers=self._header_dict1, data=data)
        if json.loads(login_response.text)["status"] != 'success':
            raise Exception("Login Error %s" % ((login_response.text),))
        self.cookies_data.update(login_response.cookies.get_dict())
        self.cookies_data.pop("request_id")
        login_response = self.reqsession.get('https://kite.zerodha.com/dashboard', headers=self._header_dict2, cookies=self.cookies_data)
        
    def set_session_expiry_hook(self, method):
        """
        Set a callback hook for session (`TokenError` -- timeout, expiry etc.) errors.

        An `access_token` (login session) can become invalid for a number of
        reasons, but it doesn't make sense for the client to
        try and catch it during every API call.

        A callback method that handles session errors
        can be set here and when the client encounters
        a token error at any point, it'll be called.

        This callback, for instance, can log the user out of the UI,
        clear session cookies, or initiate a fresh login.
        """
        if not callable(method):
            raise TypeError("Invalid input type. Only functions are accepted.")

        self.session_expiry_hook = method


  
    def margins(self, segment=None):
        """Get account balance and cash margin details for a particular segment.

        - `segment` is the trading segment (eg: equity or commodity)
        """
        if segment:
            return self._get("user.margins.segment", url_args={"segment": segment})
        else:
            return self._get("user.margins")
            '''
            # Custom headers
            headers = {
                "X-Kite-Version": "3",  # For version 3
                "User-Agent": self._user_agent()
            }
            # set authorization header
            headers["authorization"] = "enctoken {}".format(self.cookies_data['enctoken'])
            return self.reqsession.get('https://kite.zerodha.com/oms/user/margins',cookies=self.cookies_data,headers=headers)
                '''
    def profile(self):
        """Get user profile details."""
        return self._get("user.profile")

    # orders
    def place_order(self,
                    variety,
                    exchange,
                    tradingsymbol,
                    transaction_type,
                    quantity,
                    product,
                    order_type,
                    price=None,
                    validity=None,
                    disclosed_quantity=None,
                    trigger_price=None,
                    squareoff=None,
                    stoploss=None,
                    trailing_stoploss=None,
                    tag=None):
        """Place an order."""
        params = locals()
        del(params["self"])

        for k in list(params.keys()):
            if params[k] is None:
                del(params[k])

        return self._post("order.place",
                          url_args={"variety": variety},
                          params=params)["order_id"]

    def modify_order(self,
                     variety,
                     order_id,
                     parent_order_id=None,
                     quantity=None,
                     price=None,
                     order_type=None,
                     trigger_price=None,
                     validity=None,
                     disclosed_quantity=None):
        """Modify an open order."""
        params = locals()
        del(params["self"])

        for k in list(params.keys()):
            if params[k] is None:
                del(params[k])

        return self._put("order.modify",
                         url_args={"variety": variety, "order_id": order_id},
                         params=params)["order_id"]

    def cancel_order(self, variety, order_id, parent_order_id=None):
        """Cancel an order."""
        return self._delete("order.cancel",
                            url_args={"variety": variety, "order_id": order_id},
                            params={"parent_order_id": parent_order_id})["order_id"]

    def exit_order(self, variety, order_id, parent_order_id=None):
        """Exit a BO/CO order."""
        return self.cancel_order(variety, order_id, parent_order_id=parent_order_id)

    def _format_response(self, data):
        """Parse and format responses."""

        if type(data) == list:
            _list = data
        elif type(data) == dict:
            _list = [data]

        for item in _list:
            # Convert date time string to datetime object
            for field in ["order_timestamp", "exchange_timestamp", "created", "last_instalment", "fill_timestamp", "timestamp", "last_trade_time"]:
                if item.get(field) and len(item[field]) == 19:
                    item[field] = dateutil.parser.parse(item[field])

        return _list[0] if type(data) == dict else _list

    # orderbook and tradebook
    def orders(self):
        """Get list of orders."""
        return self._format_response(self._get("orders"))

    def order_history(self, order_id):
        """
        Get history of individual order.

        - `order_id` is the ID of the order to retrieve order history.
        """
        return self._format_response(self._get("order.info", url_args={"order_id": order_id}))

    def trades(self):
        """
        Retrieve the list of trades executed (all or ones under a particular order).

        An order can be executed in tranches based on market conditions.
        These trades are individually recorded under an order.
        """
        return self._format_response(self._get("trades"))

    def order_trades(self, order_id):
        """
        Retrieve the list of trades executed for a particular order.

        - `order_id` is the ID of the order to retrieve trade history.
        """
        return self._format_response(self._get("order.trades", url_args={"order_id": order_id}))

    def positions(self):
        """Retrieve the list of positions."""
        return self._get("portfolio.positions")

    def holdings(self):
        """Retrieve the list of equity holdings."""
        return self._get("portfolio.holdings")

    def convert_position(self,
                         exchange,
                         tradingsymbol,
                         transaction_type,
                         position_type,
                         quantity,
                         old_product,
                         new_product):
        """Modify an open position's product type."""
        return self._put("portfolio.positions.convert", params={
            "exchange": exchange,
            "tradingsymbol": tradingsymbol,
            "transaction_type": transaction_type,
            "position_type": position_type,
            "quantity": quantity,
            "old_product": old_product,
            "new_product": new_product
        })

    def order_margins(self, params):
        """
        Calculate margins for requested order list considering the existing positions and open orders

        - `params` is list of orders to retrive margins detail
        """
        return self._post("order.margins", params=params, is_json=True)

    def basket_order_margins(self, params, consider_positions=True, mode=None):
        """
        Calculate total margins required for basket of orders including margin benefits

        - `params` is list of orders to fetch basket margin
        - `consider_positions` is a boolean to consider users positions
        - `mode` is margin response mode type. compact - Compact mode will only give the total margins
        """
        return self._post("order.margins.basket",
                          params=params,
                          is_json=True,
                          query_params={'consider_positions': consider_positions, 'mode': mode})
    def instruments(self, exchange=None):
        """
        Retrieve the list of market instruments available to trade.
        Note that the results could be large, several hundred KBs in size,
        with tens of thousands of entries in the list.
        - `exchange` is specific exchange to fetch (Optional)
        """
        if exchange:
            return self._parse_instruments(self._get("market.instruments", url_args={"exchange": exchange}))
        else:
            return self._parse_instruments(self._get("market.instruments.all"))
#############
    def quote(self, *instruments):
        """
        Retrieve quote for list of instruments.
        - `instruments` is a list of instruments, Instrument are in the format of `exchange:tradingsymbol`. For example NSE:INFY
        """
        ins = list(instruments)

        # If first element is a list then accept it as instruments list for legacy reason
        if len(instruments) > 0 and type(instruments[0]) == list:
            ins = instruments[0]

        data = self._get("market.quote", params={"i": ins})
        return {key: self._format_response(data[key]) for key in data}

    def ohlc(self, *instruments):
        """
        Retrieve OHLC and market depth for list of instruments.
        - `instruments` is a list of instruments, Instrument are in the format of `exchange:tradingsymbol`. For example NSE:INFY
        """
        ins = list(instruments)

        # If first element is a list then accept it as instruments list for legacy reason
        if len(instruments) > 0 and type(instruments[0]) == list:
            ins = instruments[0]

        return self._get("market.quote.ohlc", params={"i": ins})

    def ltp(self, *instruments):
        """
        Retrieve last price for list of instruments.
        - `instruments` is a list of instruments, Instrument are in the format of `exchange:tradingsymbol`. For example NSE:INFY
        """
        ins = list(instruments)

        # If first element is a list then accept it as instruments list for legacy reason
        if len(instruments) > 0 and type(instruments[0]) == list:
            ins = instruments[0]

        return self._get("market.quote.ltp", params={"i": ins})
    ########
    def historical_data(self, instrument_token, from_date, to_date, interval, continuous=False, oi=False):
        """
        Retrieve historical data (candles) for an instrument.
        Although the actual response JSON from the API does not have field
        names such has 'open', 'high' etc., this function call structures
        the data into an array of objects with field names. For example:
        - `instrument_token` is the instrument identifier (retrieved from the instruments()) call.
        - `from_date` is the From date (datetime object or string in format of yyyy-mm-dd HH:MM:SS.
        - `to_date` is the To date (datetime object or string in format of yyyy-mm-dd HH:MM:SS).
        - `interval` is the candle interval (minute, day, 5 minute etc.).
        - `continuous` is a boolean flag to get continuous data for futures and options instruments.
        - `oi` is a boolean flag to get open interest.
        """
        date_string_format = "%Y-%m-%d %H:%M:%S"
        from_date_string = from_date.strftime(date_string_format) if type(from_date) == datetime.datetime else from_date
        to_date_string = to_date.strftime(date_string_format) if type(to_date) == datetime.datetime else to_date

        data = self._get("market.historical",
                         url_args={"instrument_token": instrument_token, "interval": interval},
                         params={
                             "from": from_date_string,
                             "to": to_date_string,
                             "interval": interval,
                             "continuous": 1 if continuous else 0,
                             "oi": 1 if oi else 0
                         })

        return self._format_historical(data)

    def _format_historical(self, data):
        records = []
        for d in data["candles"]:
            record = {
                "date": dateutil.parser.parse(d[0]),
                "open": d[1],
                "high": d[2],
                "low": d[3],
                "close": d[4],
                "volume": d[5],
            }
            if len(d) == 7:
                record["oi"] = d[6]
            records.append(record)

        return records
    
    
    def _user_agent(self):
        return ("kiteconnect" + "-python/").capitalize() + "3.9.4"

    def _get(self, route, url_args=None, params=None, is_json=False):
        """Alias for sending a GET request."""
        return self._request(route, "GET", url_args=url_args, params=params, is_json=is_json)

    def _post(self, route, url_args=None, params=None, is_json=False, query_params=None):
        """Alias for sending a POST request."""
        return self._request(route, "POST", url_args=url_args, params=params, is_json=is_json, query_params=query_params)

    def _put(self, route, url_args=None, params=None, is_json=False, query_params=None):
        """Alias for sending a PUT request."""
        return self._request(route, "PUT", url_args=url_args, params=params, is_json=is_json, query_params=query_params)

    def _delete(self, route, url_args=None, params=None, is_json=False):
        """Alias for sending a DELETE request."""
        return self._request(route, "DELETE", url_args=url_args, params=params, is_json=is_json)

    def _request(self, route, method, url_args=None, params=None, is_json=False, query_params=None):
        """Make an HTTP request."""
        # Form a restful URL
        if url_args:
            uri = self._routes[route].format(**url_args)
        else:
            uri = self._routes[route]

        url = urljoin(self.root, uri)

        print('Redirect url : ',url)
        # Custom headers
        headers = {
            "X-Kite-Version": "3",  # For version 3
            "User-Agent": 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.146 Safari/537.36'
        }

            # set authorization header
        headers["authorization"] = "enctoken {}".format(self.cookies_data['enctoken'])
#         print(headers)
        if self.debug:
            log.debug("Request: {method} {url} {params} {headers}".format(method=method, url=url, params=params, headers=headers))

        # prepare url query params
        if method in ["GET", "DELETE"]:
#             print('GET method called')
            query_params = params
#             print('Query params :',query_params)
        try:
#             self.reqsession = requests
#             r = self.reqsession.request(method,
#                                         url,
#                                         json=params if (method in ["POST", "PUT"] and is_json) else None,
#                                         data=params if (method in ["POST", "PUT"] and not is_json) else None,
#                                         params=query_params,
#                                         headers=headers,
#                                         verify=not self.disable_ssl,
#                                         allow_redirects=True,
#                                         timeout=self.timeout,
#                                         proxies=self.proxies)
            r=requests.request(method,
                                        url,
                                        json=params if (method in ["POST", "PUT"] and is_json) else None,
                                        data=params if (method in ["POST", "PUT"] and not is_json) else None,
                                        params=query_params,
                                        headers=headers,
                                        verify=not self.disable_ssl,
                                        allow_redirects=True,
                                        timeout=self.timeout,
                                        proxies=self.proxies,cookies=self.cookies_data)
#             print(r.text)
#         try:
#             if method == 'GET':
# #                 r = self.reqsession.get(url,headers=headers,cookies=self.cookies_data)
#                 r= self.reqsession.get('https://kite.zerodha.com/oms/user/margins',cookies=self.cookies_data,headers=headers)
#                 return r
        # Any requests lib related exceptions are raised here - http://docs.python-requests.org/en/master/_modules/requests/exceptions/
        except Exception as e:
            raise e

        if self.debug:
            log.debug("Response: {code} {content}".format(code=r.status_code, content=r.content))

        # Validate the content type.
        if "json" in r.headers["content-type"]:
            try:
                data = json.loads(r.content.decode("utf8"))
            except ValueError:
                raise ex.DataException("Couldn't parse the JSON response received from the server: {content}".format(
                    content=r.content))

            # api error
            if data.get("status") == "error" or data.get("error_type"):
                # Call session hook if its registered and TokenException is raised
                if self.session_expiry_hook and r.status_code == 403 and data["error_type"] == "TokenException":
                    self.session_expiry_hook()

                # native Kite errors
                exp = getattr(ex, data.get("error_type"), ex.GeneralException)
                raise exp(data["message"], code=r.status_code)

            return data["data"]
        elif "csv" in r.headers["content-type"]:
            return r.content
        else:
            raise ex.DataException("Unknown Content-Type ({content_type}) with response: ({content})".format(
                content_type=r.headers["content-type"],
                content=r.content))

