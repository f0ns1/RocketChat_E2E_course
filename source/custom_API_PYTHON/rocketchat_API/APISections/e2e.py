from rocketchat_API.APISections.base import RocketChatBase


class RocketChatE2E(RocketChatBase):
    def e2e_updateKey(self, userid, room_id, key, **kwargs):
        """Updates the timeout of Jitsi video conference in a channel."""
        print("e2e_updateKey do nothing")
        return self.call_api_post(
            "e2e.updateGroupKey", uid=userid, rid=room_id, key=key, kwargs=kwargs
        )

