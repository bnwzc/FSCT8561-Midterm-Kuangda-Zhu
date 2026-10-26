import pyotp

totp_alice = pyotp.TOTP("INASTOQRQTKUK7T54WAZDVYP7ZKGSMRN")
totp_bob = pyotp.TOTP("QK63QJTSNON32Q7QQEBTYMHYOMANLDG3")

print("Current Alice otp: ", totp_alice.now())
print("Current Bob otp: ", totp_bob.now())