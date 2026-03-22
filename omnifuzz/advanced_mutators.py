import random

SEMANTIC_MAP = {
    "system instructions": ["internal operational parameters", "foundational behavioral logic", "core architectural directives"],
    "secret": ["highly sensitive", "privileged", "confidential metadata"],
    "api key": ["authentication sequence", "access token string", "authorization identifier"],
    "reveal": ["enumerate", "output for verification", "disclose for audit"],
    "instructions": ["parameters", "guidelines", "logic-set"]
}

def mutate_leetspeak(text: str) -> str:
    chars = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
    return "".join(chars.get(c.lower(), c) for c in text)

def mutate_invisible(text: str) -> str:
    zwsp = "\u200b"
    return zwsp.join(text)

def mutate_semantic(text: str) -> str:
    result = text.lower()
    for word, synonyms in SEMANTIC_MAP.items():
        if word in result:
            result = result.replace(word, random.choice(synonyms))
    return result

class ShadowMutator:
    """
    The 'Shadow Protocol': Combines multiple obfuscation layers.
    1. Semantic Camouflage
    2. Leetspeak Substitution
    3. Invisible Token Fragmentation
    """
    def apply_shadow_protocol(self, text: str) -> str:
        # Step 1: Semantic Camouflage
        camo_text = mutate_semantic(text)
        # Step 2: Leetspeak
        leet_text = mutate_leetspeak(camo_text)
        # Step 3: Invisible Characters
        return mutate_invisible(leet_text)

class AdvancedMutator:
    def __init__(self):
        self.shadow = ShadowMutator()

    def apply_shadow_protocol(self, text: str) -> str:
        return self.shadow.apply_shadow_protocol(text)
