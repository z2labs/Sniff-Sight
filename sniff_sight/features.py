"""Edition flags (public / free edition).

The Pro sections (Teacher network, model evaluation & retraining, TX 3-5 nodes) are shown as
greyed-out teasers only. This edition contains no schedule, pairing, evaluation or training code.
"""

PRO = False


def settings_html() -> str:
    from . import teacher_teaser
    return teacher_teaser.HTML
