from __future__ import annotations
import threading
import random
import time
from typing import List, Any, Optional, Tuple, Dict

# Conditional import for Twisted reactor for GUI integration
_reactor_installed = False
try:
    from twisted.internet import reactor, tksupport
    _reactor_installed = True
except ImportError:
    print("Twisted reactor or GUI support not found. GUI integration with Twisted might require manual setup.")

# Imports from ctrader-open-api
try:
    from ctrader_open_api import Client, TcpProtocol, EndPoints
    from ctrader_open_api.messages.OpenApiCommonMessages_pb2 import (
        ProtoHeartbeatEvent,
        ProtoErrorRes,
        ProtoMessage
    )
    from ctrader_open_api.messages.OpenApiMessages_pb2 import (
        ProtoOAApplicationAuthReq, ProtoOAApplicationAuthRes,
        ProtoOAAccountAuthReq, ProtoOAAccountAuthRes,
        ProtoOAGetAccountListByAccessTokenReq, ProtoOAGetAccountListByAccessTokenRes,
        ProtoOATraderReq, ProtoOATraderRes,
        ProtoOASubscribeSpotsReq, ProtoOASubscribeSpotsRes,
        ProtoOASpotEvent, ProtoOATraderUpdatedEvent,
        ProtoOANewOrderReq, ProtoOAExecutionEvent,
        ProtoOAErrorRes
    )
    from ctrader_open_api.messages.OpenApiModelMessages_pb2 import ProtoOATrader
    USE_OPENAPI_LIB = True
except ImportError as e:
    print(f"ctrader-open-api import failed ({e}); running in mock mode.")
    USE_OPENAPI_LIB = False


class Trader:
    def __init__(self, settings, history_size: int = 100):
        self.settings = settings
        self.is_connected: bool = False
        self._is_client_connected: bool = False
        self._last_error: str = ""
        self.price_history: List[float] = []
        self.history_size = history_size
        self._access_token: Optional[str] = None

        # Account details
        self.ctid_trader_account_id: Optional[int] = settings.openapi.default_ctid_trader_account_id
        self.account_id: Optional[str] = None
        self.balance: Optional[float] = None
        self.equity: Optional[float] = None
        self.currency: Optional[str] = None

        self._client: Optional[Client] = None
        self._message_id_counter: int = 1
        self._reactor_thread: Optional[threading.Thread] = None

        if USE_OPENAPI_LIB:
            host = (
                EndPoints.PROTOBUF_LIVE_HOST
                if settings.openapi.host_type == "live"
                else EndPoints.PROTOBUF_DEMO_HOST
            )
            port = EndPoints.PROTOBUF_PORT
            self._client = Client(host, port, TcpProtocol)
            self._client.setConnectedCallback(self._on_client_connected)
            self._client.setDisconnectedCallback(self._on_client_disconnected)
            self._client.setMessageReceivedCallback(self._on_message_received)
        else:
            print("Trader initialized in MOCK mode.")

    def _next_message_id(self) -> str:
        mid = str(self._message_id_counter)
        self._message_id_counter += 1
        return mid

    # Twisted callbacks
    def _on_client_connected(self, client: Client) -> None:
        print("OpenAPI Client Connected.")
        self._is_client_connected = True
        self._last_error = ""
        req = ProtoOAApplicationAuthReq()
        req.clientId = self.settings.openapi.client_id or ""
        req.clientSecret = self.settings.openapi.client_secret or ""
        if not req.clientId or not req.clientSecret:
            print("Missing OpenAPI credentials.")
            client.stopService()
            return
        print("Sending ApplicationAuth request.")
        d = client.send(req)
        d.addCallbacks(self._handle_app_auth_response, self._handle_send_error)

    def _on_client_disconnected(self, client: Client, reason: Any) -> None:
        print(f"OpenAPI Client Disconnected: {reason}")
        self.is_connected = False
        self._is_client_connected = False

    def _on_message_received(self, client: Client, message: Any) -> None:
        # Dispatch by type
        if isinstance(message, ProtoOAApplicationAuthRes):
            self._handle_app_auth_response(message)
        elif isinstance(message, ProtoOAAccountAuthRes):
            self._handle_account_auth_response(message)
        elif isinstance(message, ProtoOAGetAccountListByAccessTokenRes):
            self._handle_get_account_list_response(message)
        elif isinstance(message, ProtoOATraderRes):
            self._handle_trader_response(message)
        elif isinstance(message, ProtoOATraderUpdatedEvent):
            self._handle_trader_updated_event(message)
        elif isinstance(message, ProtoOASpotEvent):
            self._handle_spot_event(message)
        elif isinstance(message, ProtoOAExecutionEvent):
            self._handle_execution_event(message)
        elif isinstance(message, ProtoHeartbeatEvent):
            print("Received heartbeat.")
        elif isinstance(message, ProtoOAErrorRes):
            print(f"Error message received: {message.errorCode}")
            self._last_error = message.description

    # Handlers
    def _handle_app_auth_response(self, response: ProtoOAApplicationAuthRes) -> None:
        print("ApplicationAuth response.")
        self._access_token = getattr(response, 'accessToken', None)
        if self.ctid_trader_account_id:
            self._send_account_auth_request(self.ctid_trader_account_id)
        else:
            self._send_get_account_list_request()

    def _handle_account_auth_response(self, response: ProtoOAAccountAuthRes) -> None:
        print("AccountAuth response.")
        if response.ctidTraderAccountId == self.ctid_trader_account_id:
            self.is_connected = True
            self._send_get_trader_request(self.ctid_trader_account_id)
        else:
            print("AccountAuth failed.")

    def _handle_get_account_list_response(self, response: ProtoOAGetAccountListByAccessTokenRes) -> None:
        print("Account list response.")
        accounts = getattr(response, 'ctidTraderAccount', [])
        if not accounts:
            print("No accounts available.")
            return
        self.ctid_trader_account_id = accounts[0].ctidTraderAccountId
        self.settings.openapi.default_ctid_trader_account_id = self.ctid_trader_account_id
        self._send_account_auth_request(self.ctid_trader_account_id)

    def _handle_trader_response(self, response: ProtoOATraderRes) -> None:
        trader_details = self._update_trader_details(
            "Trader details response.", response.trader
        )
        if trader_details:
            self.account_id = str(trader_details.ctidTraderAccountId)
            # Potentially other fields from trader_details could be assigned here if needed

    def _handle_trader_updated_event(self, event: ProtoOATraderUpdatedEvent) -> None:
        self._update_trader_details(
            "Trader updated event.", event.trader
        )

    def _update_trader_details(self, log_message: str, trader_proto: ProtoOATrader):
        """Helper to update trader balance and equity from a ProtoOATrader object."""
        print(log_message)
        if trader_proto:
            self.balance = trader_proto.balance / 100.0  # Assuming balance is in cents
            self.equity = trader_proto.equity / 100.0    # Assuming equity is in cents
            # self.currency = trader_proto.currency # If currency is available and needed
            # self.ctid_trader_account_id = trader_proto.ctidTraderAccountId # Already known, but can confirm
            print(f"Updated account {trader_proto.ctidTraderAccountId}: Balance: {self.balance}, Equity: {self.equity}")
            return trader_proto
        return None

    def _handle_spot_event(self, event: ProtoOASpotEvent) -> None:
        # TODO: update self.price_history
        pass

    def _handle_execution_event(self, event: ProtoOAExecutionEvent) -> None:
        # TODO: handle executions
        pass

    def _handle_send_error(self, failure: Any) -> None:
        print(f"Send error: {failure.getErrorMessage()}")
        self._last_error = failure.getErrorMessage()

    # Sending methods
    def _send_account_auth_request(self, ctid: int) -> None:
        print(f"Requesting AccountAuth for {ctid}")
        req = ProtoOAAccountAuthReq()
        req.ctidTraderAccountId = ctid
        req.accessToken = self._access_token or ""
        d = self._client.send(req)
        # Only error callback; normal messages handled in _on_message_received
        d.addErrback(self._handle_send_error)

    def _send_get_account_list_request(self) -> None:
        print("Requesting account list.")
        req = ProtoOAGetAccountListByAccessTokenReq()
        d = self._client.send(req)
        d.addCallbacks(self._handle_get_account_list_response, self._handle_send_error)

    def _send_get_trader_request(self, ctid: int) -> None:
        print(f"Requesting Trader details for {ctid}")
        req = ProtoOATraderReq()
        req.ctidTraderAccountId = ctid
        d = self._client.send(req)
        d.addCallbacks(self._handle_trader_response, self._handle_send_error)

    # Public API
    def connect(self) -> bool:
        if not USE_OPENAPI_LIB:
            print("Mock mode: OpenAPI library unavailable.")
            return False
        if self.is_connected or (self._client and getattr(self._client, 'isConnected', False)):
            return True
        print("Starting OpenAPI service.")
        try:
            self._client.startService()
            # Start reactor if needed
            if _reactor_installed and not reactor.running:
                thread = threading.Thread(target=lambda: reactor.run(installSignalHandlers=0), daemon=True)
                thread.start()
            return True
        except Exception as e:
            print(f"Connection error: {e}")
            self._last_error = str(e)
            return False

    def disconnect(self) -> None:
        if self._client:
            self._client.stopService()
        if _reactor_installed and reactor.running:
            reactor.callFromThread(reactor.stop)
        self.is_connected = False
        self._is_client_connected = False

    def get_connection_status(self) -> Tuple[bool, str]:
        return self.is_connected, self._last_error

    def get_account_summary(self) -> Dict[str, Any]:
        if not USE_OPENAPI_LIB:
            return {"account_id": "MOCK", "balance": 0.0, "equity": 0.0}
        if not self.is_connected:
            return {"account_id": "connecting..."}
        return {"account_id": self.account_id, "balance": self.balance, "equity": self.equity}

    def get_market_price(self, symbol: str) -> float:
        if not USE_OPENAPI_LIB or not self.price_history:
            return round(random.uniform(1.10, 1.20), 5)
        return self.price_history[-1]

    def get_price_history(self) -> List[float]:
        return list(self.price_history)
