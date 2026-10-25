# defines a standard constant
KEY_REQUEST = "KEY_REQUEST"
KEY_RESPONSE = "KEY_RESPONSE"
SESSION_TICKET = "SESSION_TICKET"
SESSION_CONFIRM = "SESSION_CONFIRM"
CHAT_MESSAGE = "CHAT_MESSAGE"
CHAT_RESPONSE = "CHAT_RESPONSE"
ERROR = "ERROR"


def create_message(message_type: str, **fields) -> dict:
    if not isinstance(message_type, str) or not message_type:
        raise ValueError("message_type must be a non-empty string")

    return {
        "type": message_type,
        **fields,
    }

def validate_message(message: object) -> dict:
    if not isinstance(message, dict):
        raise ValueError("Message must be a JSON object")

    if not isinstance(message.get("type"), str):
        raise ValueError("Message must contain a string 'type' field")

    return message
