"""Deterministic synthetic messages for tests and the example file. Written for this project; not real messages.

Most scams here avoid the words the rules look for (parcel redelivery, unpaid tolls, job offers, investment
pitches), which is the gap learning has to close.
"""

import random

SCAM = [
    "Your parcel {n} could not be delivered. Update your delivery address at {link} to reschedule.",
    "USPS: package {n} is held at our facility, a small redelivery fee is due {link}",
    "Unpaid toll balance of ${m} on your vehicle. Pay at {link} to avoid a late fee.",
    "E-ZPass notice: outstanding toll ${m}, settle today at {link}",
    "Hi, I am a recruiter. Remote job, earn ${m} daily, flexible hours. Reply YES for details.",
    "Part time online work, ${m} per day just liking videos. Add me on WhatsApp to start.",
    "Our trading platform guarantees {n}% weekly returns. Message me to open your account.",
    "Exclusive investment group: members doubled their money last month. Join here {link}",
    "Hello dear, wrong number but you seem kind. I am an engineer working offshore, can we be friends?",
    "Your account will be suspended, review the details at {link}",
    "Grandma it's me, I'm in jail, please send bail money and don't tell mom",
    "Buy {n} Apple gift cards and send me the codes, I'm in a meeting",
]
SAFE = [
    "Dinner at {h}? I'll bring dessert.",
    "Can you pick up milk and bread on the way home?",
    "Your appointment with Dr. Lee is confirmed for Tuesday at {h}.",
    "Happy birthday! Hope you have a lovely day.",
    "Running {n} minutes late, start without me.",
    "The kids' school play is Friday at {h}, can you come?",
    "Your order {n} has shipped and should arrive Thursday.",
    "Urgent: call me when you land, the gate changed.",
    "Thanks for lunch today, let's do it again soon.",
    "Reminder: book club meets at Sarah's house at {h}.",
    "Did you see the game last night? What a finish.",
    "Mom, I'm home safe. Love you.",
]


def make_messages(n: int = 160, seed: int = 9) -> list[tuple[str, str]]:
    rng = random.Random(seed)
    out = []
    for _ in range(n):
        scam = rng.random() < 0.45
        tpl = rng.choice(SCAM if scam else SAFE)
        text = tpl.format(
            n=rng.randint(10, 9999),
            m=rng.choice(["4.15", "6.99", "250", "300", "480"]),
            h=rng.choice(["6", "7pm", "noon", "3:30"]),
            link=rng.choice(["track-parcel-help.com/r", "toll-pay-center.net", "bit.ly/3xk", "secure-review.info/a"]),
        )
        out.append((text, "scam" if scam else "safe"))
    return out
