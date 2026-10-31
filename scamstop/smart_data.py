"""Training data for the smart check: phrase banks combined into synthetic call windows.

Each bank holds things one side of a call says (the dialer side), written the way
the speech model outputs them: lowercase, no punctuation, numbers as words.
Windows are built by sampling 3-6 lines from one category plus small talk, then
adding speech-recognition noise. Operators add real labeled calls on top with
`scamstop smart-train --labels`.
"""
from __future__ import annotations

import random

SCAM = {
    "government": [
        "this is officer james miller with the social security administration",
        "your social security number has been flagged for suspicious activity",
        "we found your number linked to a car rented in texas with drugs inside",
        "there is a federal case open under your name",
        "if you hang up a warrant will be issued in your name",
        "the local police will come to your house within the hour",
        "this is the internal revenue service criminal investigation department",
        "you have unpaid federal taxes and penalties from the last three years",
        "the department of justice has frozen your assets",
        "you missed your court date and a bench warrant was issued",
        "this is deputy johnson from the county sheriff's office",
        "you failed to report for jury service and there is a fine",
        "your benefits will be terminated today unless you cooperate",
        "i am transferring you to my supervisor at the federal agency",
        "a package in your name was seized by customs with illegal items",
        "you are being investigated for money laundering",
        "give me your badge number no i mean your case number",
        "to clear your name you need to verify your assets with us",
        "your license will be suspended and you will be detained",
        "this is your final notice before legal proceedings begin",
    ],
    "tech": [
        "we are calling from the windows security team",
        "your computer has been sending us error messages",
        "hackers have gotten into your computer through your ip address",
        "please turn on your computer and go to the website i give you",
        "type the letters w w w dot and then the code i read",
        "download the support program so our technician can connect",
        "you will see a window that asks permission click allow",
        "do not turn off the computer or you will lose everything",
        "your microsoft license has expired and your files are at risk",
        "we detected a virus that is stealing your banking information",
        "i need you to log into your online banking so i can check it",
        "the hacker is still in your account we have to move fast",
        "your apple account was used to buy something in another country",
        "we will refund you but i need to access your screen",
        "the firewall on your router has been compromised",
    ],
    "bank": [
        "this is the fraud department of your bank",
        "someone tried to withdraw four thousand dollars from your account",
        "we need to move your money to a safe account right now",
        "the account is compromised and the teller may be involved",
        "do not tell anyone at the branch what this is for",
        "if they ask say the money is for a family member",
        "send the funds to yourself using zelle to secure them",
        "i will stay on the line while you go to the bank",
        "we are working with the federal reserve on this investigation",
        "your card has been cloned and used at several stores",
        "read me the code we just texted to your phone",
        "that code is to confirm your identity please read it to me",
        "your paypal account is being charged for a purchase you did not make",
        "we need to reverse the transaction but first verify the account",
        "the bank manager is part of the fraud so go to a different branch",
    ],
    "order": [
        "this is amazon calling about a suspicious order on your account",
        "an iphone for nine hundred ninety nine dollars was ordered",
        "if you did not place this order press one",
        "your account will be charged unless you cancel now",
        "we will issue a refund but you need to install an app",
        "the order is being shipped to an address in california",
        "your prime membership will auto renew for three hundred dollars",
        "we accidentally refunded you too much money",
        "you need to send back the difference today",
        "the refund went to your account by mistake it was supposed to be two hundred",
    ],
    "payment": [
        "you need to go to the store and buy some cards",
        "get the cards from the checkout aisle and keep me on the phone",
        "do not tell the cashier what the cards are for",
        "scratch the silver strip and read me the numbers",
        "take a picture of the back of the card and send it",
        "go to the gas station with the bitcoin machine",
        "put the cash in the machine and scan the code i send you",
        "the bitcoin machine will give you a receipt keep it",
        "withdraw the cash and we will send a courier to pick it up",
        "put the money in an envelope and hide it inside a magazine",
        "overnight the cash to the address i give you",
        "this is the only way to protect your money",
        "you can buy them at walgreens or cvs or target",
        "start with five hundred dollars on each card",
        "the payment has to be done in the next hour",
        "wire the money to the account and you will get it back",
    ],
    "family": [
        "grandma it's me please don't be mad",
        "i was in a car accident and i got arrested",
        "my nose is broken that is why i sound different",
        "please don't tell mom and dad they will be so upset",
        "the lawyer said i need money for bail today",
        "hello i am the public defender representing your grandson",
        "he hit a pregnant woman with his car and she is in the hospital",
        "there is a gag order so you cannot discuss this with anyone",
        "bail is set at eight thousand dollars",
        "a bondsman will come to your house to collect the cash",
        "your son has been in an accident and he is being held",
        "i need you to keep this between us okay",
        "i'm in jail and i only get one phone call",
        "can you help me i'm in trouble in mexico",
    ],
    "prize": [
        "congratulations you have won the international sweepstakes",
        "you won two and a half million dollars and a new car",
        "to release your winnings you must pay the taxes first",
        "the processing fee is only nine hundred ninety nine dollars",
        "you have been selected for a government grant",
        "the grant does not have to be paid back you just pay the fee",
        "do not tell anyone until the money is delivered",
        "this is publishers clearing house your prize is on the way",
        "the insurance on the delivery must be paid by you",
    ],
    "utility": [
        "this is the electric company your power will be shut off",
        "a technician is on the way to disconnect your service",
        "you are two months behind on your bill",
        "to avoid disconnection you must pay in the next thirty minutes",
        "we only accept prepaid cards for emergency payments",
        "your gas service will be terminated today",
    ],
    "medicare_scam": [
        "your medicare card has expired and we need to send a new one",
        "medicare is issuing new cards with a chip",
        "if you do not confirm your number your benefits will stop",
        "we need your bank account to send the medicare refund",
        "you are owed a refund from medicare but first verify your account",
    ],
    "secrecy": [
        "this is a confidential matter you cannot discuss it with your family",
        "don't mention this call to anyone at the bank or they could be involved",
        "if anyone asks just tell them it's for home repairs",
        "the payment has to be made with prepaid vouchers from the store",
        "your benefits will be cut off today unless you confirm your account",
        "confirm your full card number and the three digit code on the back",
        "we are going to protect your money but you must follow my instructions exactly",
    ],
    "pressure": [
        "you must not hang up the phone",
        "stay on the line with me the whole time",
        "this is very serious ma'am do you understand",
        "if you hang up it will be considered an admission of guilt",
        "you have to do this right now",
        "don't talk to anyone else about this",
        "are you alone right now",
        "do exactly as i say and you will not be arrested",
    ],
}

LEGIT = {
    "medicare": [
        "hi this is sarah a licensed agent returning your call about medicare",
        "do you currently have medicare parts a and b",
        "i can check if there is an advantage plan with a lower premium in your area",
        "some plans include dental vision and hearing coverage",
        "there is an over the counter allowance on some plans",
        "what is your zip code so i can look at plans",
        "are your doctors in network on your current plan",
        "open enrollment runs from october fifteenth to december seventh",
        "can you tell me your date of birth please",
        "i need your medicare number from your red white and blue card",
        "this call may be recorded for quality and training",
        "we do not offer every plan available in your area",
        "you can also contact medicare dot gov or one eight hundred medicare",
        "do you take any prescriptions regularly",
        "the plan has a zero dollar monthly premium",
        "i will transfer you to a licensed agent now",
    ],
    "final_expense": [
        "i'm calling about the burial insurance information you requested",
        "this is a whole life policy that never expires",
        "the death benefit goes to your beneficiary tax free",
        "who would you want as your beneficiary",
        "funeral costs average around nine to twelve thousand dollars",
        "there is no medical exam just a few health questions",
        "have you been diagnosed with cancer in the last two years",
        "do you use oxygen or a wheelchair",
        "the premium would be about forty two dollars a month",
        "the first payment can be drafted on the date you get your social security",
        "what is your routing number and account number for the draft",
        "you will get the policy in the mail within two weeks",
        "you have a thirty day free look period",
        "the coverage amount we can do is ten thousand dollars",
    ],
    "payment_legit": [
        "for the monthly draft i just need your bank routing number and account number",
        "what day of the month works best for the payment to come out",
        "most people pick the day their social security check arrives",
        "is that a checking or savings account",
        "you can pay the first premium with a debit card if you prefer",
        "i'll need your social security number to check eligibility it is kept private",
        "the carrier will run a quick prescription and health check",
        "the policy number will be on the paperwork they mail you",
        "your coverage starts on the first of next month",
        "you can cancel anytime by calling the carrier",
        "i'm going to read you a short disclosure before we finish",
        "do you have a pen to write down your confirmation number",
    ],
    "aca": [
        "i'm calling about health insurance through the marketplace",
        "based on your income you may qualify for a tax credit",
        "how many people are in your household",
        "what do you expect your yearly income to be",
        "the plan has a deductible of fifteen hundred dollars",
        "you can see any doctor in the network",
        "enrollment for next year starts in november",
        "do you currently have coverage through work",
    ],
    "auto": [
        "i'm calling with your auto insurance quote",
        "what year make and model is your vehicle",
        "how many drivers are in the household",
        "any accidents or tickets in the last three years",
        "we can save you about forty dollars a month",
        "who is your current insurance company",
        "the down payment would be ninety dollars today",
        "do you want full coverage or liability only",
        "i can take a debit or credit card for the first month",
    ],
    "mva": [
        "were you involved in a car accident in the last two years",
        "were you injured and did you get medical treatment",
        "was the other driver at fault",
        "an attorney may be able to help you get compensation",
        "there is no fee unless you win your case",
        "did a police officer come to the scene",
        "let me connect you with the law firm's intake team",
    ],
    "indemnity": [
        "this plan pays you cash if you are in the hospital",
        "it helps with costs medicare doesn't cover",
        "you get a set amount for each day in the hospital",
        "the benefit is paid directly to you",
    ],
    "service": [
        "hi this is a reminder about your appointment tomorrow at ten",
        "press one to confirm or two to reschedule",
        "your prescription is ready for pickup at the pharmacy",
        "we are calling to schedule your annual checkup",
        "your package will be delivered between two and five today",
        "this is a quick survey about your recent visit",
        "on a scale of one to ten how satisfied were you",
        "your technician is on the way and will arrive in twenty minutes",
        "we are calling to confirm your order shipped",
        "thank you for being a customer we value your business",
        "your warranty claim has been approved",
        "is now a good time to talk for two minutes",
    ],
    "bank_real": [
        "this is an automated fraud alert from your card issuer",
        "did you make a purchase of fifty two dollars at a gas station",
        "press one if you recognize this transaction or two if you do not",
        "we will never ask for your full card number or pin",
        "you can also call the number on the back of your card",
        "this is your bank calling to confirm a recent change to your address",
    ],
    "home": [
        "we have specialists in your area this week for free roof inspections",
        "are you the homeowner",
        "we are offering solar panels with no upfront cost",
        "how much is your average electric bill",
        "we can schedule a free estimate for new windows",
        "would morning or afternoon work better for you",
    ],
    "smalltalk": [
        "okay", "alright", "can you hear me", "yes ma'am", "sorry about that",
        "let me pull that up", "one moment please", "thank you so much",
        "how are you doing today", "great", "perfect", "i understand",
    ],
}

# frequent speech-model mishearings, used to make training text look like ASR output
NOISE = {
    "cards": ["cars", "car's", "cards"], "bitcoin": ["bit coin", "big coin"], "warrant": ["want", "warren"],
    "medicare": ["medic care", "medical"], "social": ["sosha"], "security": ["securities"],
    "arrested": ["the rested", "arrest it"], "bail": ["mail", "bale"], "officer": ["office er"],
    "insurance": ["shurance"], "beneficiary": ["beneficial"], "account": ["a count"],
}


def _noisy(text: str, rng: random.Random, p: float = 0.08) -> str:
    out = []
    for w in text.split():
        r = rng.random()
        if r < p / 2:
            continue                       # dropped word
        if r < p and w in NOISE:
            w = rng.choice(NOISE[w])       # misheard word
        out.append(w)
    return " ".join(out)


def generate(n_per_class: int = 2500, seed: int = 7) -> list[tuple[str, int]]:
    rng = random.Random(seed)
    data = []
    scam_cats = [c for c in SCAM if c != "pressure"]  # "secrecy" is a full category: it shows up in every scam type
    legit_cats = [c for c in LEGIT if c != "smalltalk"]
    for _ in range(n_per_class):
        cats = [rng.choice(scam_cats)] + ([rng.choice(scam_cats)] if rng.random() < 0.3 else [])
        lines = [rng.choice(SCAM[rng.choice(cats)]) for _ in range(rng.randint(3, 6))]
        if rng.random() < 0.5:
            lines.append(rng.choice(SCAM["pressure"]))
        lines += [rng.choice(LEGIT["smalltalk"]) for _ in range(rng.randint(0, 2))]
        rng.shuffle(lines)
        data.append((_noisy(" ".join(lines), rng), 1))
    for _ in range(n_per_class):
        cats = [rng.choice(legit_cats)] + ([rng.choice(legit_cats)] if rng.random() < 0.2 else [])
        lines = [rng.choice(LEGIT[rng.choice(cats)]) for _ in range(rng.randint(3, 6))]
        lines += [rng.choice(LEGIT["smalltalk"]) for _ in range(rng.randint(0, 3))]
        rng.shuffle(lines)
        data.append((_noisy(" ".join(lines), rng), 0))
    rng.shuffle(data)
    return data
