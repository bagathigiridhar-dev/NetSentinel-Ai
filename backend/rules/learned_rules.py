import json
import os
import re


# ============================================================
# LEARNED RULE STORAGE
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

DATA_DIR = os.path.join(
    BASE_DIR,
    "data"
)

LEARNED_RULES_FILE = os.path.join(
    DATA_DIR,
    "learned_mappings.json"
)


# ============================================================
# ENSURE STORAGE EXISTS
# ============================================================

def ensure_storage():

    os.makedirs(
        DATA_DIR,
        exist_ok=True
    )

    if not os.path.exists(
        LEARNED_RULES_FILE
    ):

        with open(
            LEARNED_RULES_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                [],
                file,
                indent=2
            )


# ============================================================
# LOAD LEARNED MAPPINGS
# ============================================================

def load_learned_mappings():

    ensure_storage()

    try:

        with open(
            LEARNED_RULES_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(
                file
            )

            if isinstance(
                data,
                list
            ):

                return data

            return []

    except (
        json.JSONDecodeError,
        OSError
    ):

        return []


# ============================================================
# NORMALIZE COMMAND FOR MATCHING
# ============================================================

def normalize_command(command):

    if command is None:

        return ""

    command = str(
        command
    ).strip().lower()

    # Remove repeated whitespace

    command = re.sub(
        r"\s+",
        " ",
        command
    )

    return command


# ============================================================
# COMMAND TOKEN SIMILARITY
# ============================================================

def command_similarity(
    command_a,
    command_b
):

    a = set(
        normalize_command(
            command_a
        ).split()
    )

    b = set(
        normalize_command(
            command_b
        ).split()
    )

    if not a or not b:

        return 0.0

    intersection = len(
        a.intersection(b)
    )

    union = len(
        a.union(b)
    )

    return intersection / union


# ============================================================
# FIND EXACT LEARNED MAPPING
# ============================================================

def find_matching_learned_mapping(
    command
):

    mappings = load_learned_mappings()

    normalized_command = normalize_command(
        command
    )

    # --------------------------------------------------------
    # EXACT MATCH
    # --------------------------------------------------------

    for mapping in mappings:

        learned_command = normalize_command(
            mapping.get(
                "command",
                ""
            )
        )

        if (
            learned_command
            and
            learned_command
            == normalized_command
        ):

            return mapping

    # --------------------------------------------------------
    # SAFE SIMILARITY MATCH
    # --------------------------------------------------------

    best_mapping = None

    best_score = 0.0

    for mapping in mappings:

        learned_command = mapping.get(
            "command",
            ""
        )

        score = command_similarity(

            command,

            learned_command

        )

        if score > best_score:

            best_score = score

            best_mapping = mapping

    # Only accept a sufficiently similar pattern

    if (
        best_mapping
        and
        best_score >= 0.75
    ):

        return best_mapping

    return None


# ============================================================
# ADD LEARNED MAPPING
# ============================================================

def add_learned_mapping(

    command,

    category,

    parameter,

    value,

    severity="MEDIUM"

):

    mappings = load_learned_mappings()

    normalized_command = normalize_command(
        command
    )

    # --------------------------------------------------------
    # UPDATE EXISTING MAPPING
    # --------------------------------------------------------

    for mapping in mappings:

        if normalize_command(
            mapping.get(
                "command",
                ""
            )
        ) == normalized_command:

            mapping["category"] = category

            mapping["parameter"] = parameter

            mapping["value"] = value

            mapping["severity"] = severity

            mapping["source"] = "administrator_training"

            mapping["status"] = "active"

            with open(
                LEARNED_RULES_FILE,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    mappings,
                    file,
                    indent=2
                )

            return mapping

    # --------------------------------------------------------
    # CREATE NEW MAPPING
    # --------------------------------------------------------

    mapping = {

        "command": command,

        "normalized_command":
            normalized_command,

        "category": category,

        "parameter": parameter,

        "value": value,

        "severity": severity,

        "source":
            "administrator_training",

        "status":
            "active"

    }

    mappings.append(
        mapping
    )

    # --------------------------------------------------------
    # SAVE
    # --------------------------------------------------------

    with open(
        LEARNED_RULES_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            mappings,
            file,
            indent=2
        )

    return mapping


# ============================================================
# REMOVE LEARNED MAPPING
# ============================================================

def remove_learned_mapping(
    command
):

    mappings = load_learned_mappings()

    normalized_command = normalize_command(
        command
    )

    updated = []

    removed = False

    for mapping in mappings:

        if normalize_command(
            mapping.get(
                "command",
                ""
            )
        ) == normalized_command:

            removed = True

            continue

        updated.append(
            mapping
        )

    with open(
        LEARNED_RULES_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            updated,
            file,
            indent=2
        )

    return removed


# ============================================================
# LEARNING STATISTICS
# ============================================================

def get_learning_statistics():

    mappings = load_learned_mappings()

    categories = {}

    parameters = {}

    for mapping in mappings:

        category = mapping.get(
            "category",
            "unknown"
        )

        parameter = mapping.get(
            "parameter",
            "unknown"
        )

        categories[category] = (
            categories.get(
                category,
                0
            ) + 1
        )

        parameters[parameter] = (
            parameters.get(
                parameter,
                0
            ) + 1
        )

    return {

        "total":
            len(mappings),

        "categories":
            categories,

        "parameters":
            parameters

    }