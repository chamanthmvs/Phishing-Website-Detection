# coding: utf-8
"""Generate a diverse set of *realistic legitimate* deep-link URLs.

The original legitimate dataset is almost entirely short homepages, which biased
the model into treating any long URL as phishing (flagging real pages on GitHub,
Wikipedia, Amazon, etc.). This script produces realistic deep links on well-known
domains -- articles, product pages, profiles, docs, search results, videos -- so
the model learns that legitimate sites also have long, parameter-rich URLs and
must rely on genuine phishing signals instead of raw length.

Output is written to ``raw_datasets/legitimate_deeplinks.txt`` and is fully
deterministic (seeded), so the dataset can be regenerated and audited.

Run with::

    python scripts/generate_legit_deeplinks.py
"""

from __future__ import annotations

import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "raw_datasets" / "legitimate_deeplinks.txt"

SEED = 20240101

WORDS = [
    "introduction", "guide", "overview", "tutorial", "review", "analysis",
    "update", "report", "history", "design", "performance", "security",
    "machine-learning", "data-science", "climate", "economy", "health",
    "travel", "recipes", "football", "science", "python", "javascript",
    "research", "interview", "feature", "release", "roadmap", "comparison",
    "best-practices", "getting-started", "deep-dive", "case-study", "benchmark",
]

SLUG_TAILS = [
    "what-you-need-to-know", "a-complete-guide", "explained", "in-2024",
    "for-beginners", "step-by-step", "the-definitive-list", "tips-and-tricks",
    "part-1", "final-thoughts", "everything-explained", "and-more",
]


def slug(rng: random.Random, n_min=1, n_max=4) -> str:
    parts = rng.sample(WORDS, rng.randint(n_min, min(n_max, len(WORDS))))
    if rng.random() < 0.4:
        parts.append(rng.choice(SLUG_TAILS))
    return "-".join(parts)


def rand_id(rng: random.Random, length=8) -> str:
    alphabet = "ABCDEFGHIJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz0123456789"
    return "".join(rng.choice(alphabet) for _ in range(length))


def build(rng: random.Random) -> list[str]:
    urls: set[str] = set()

    # News / magazine articles with dated paths.
    news = ["nytimes.com", "theguardian.com", "bbc.com", "cnn.com",
            "washingtonpost.com", "reuters.com", "bloomberg.com", "wired.com",
            "theverge.com", "techcrunch.com", "nature.com", "forbes.com"]
    sections = ["technology", "world", "business", "science", "health",
                "sports", "culture", "opinion", "politics"]
    for _ in range(140):
        d = rng.choice(news)
        y = rng.randint(2016, 2024)
        m = rng.randint(1, 12)
        day = rng.randint(1, 28)
        urls.add(f"https://www.{d}/{rng.choice(sections)}/{y}/{m:02d}/{day:02d}/{slug(rng)}.html")

    # GitHub repositories, files and issues.
    orgs = ["torvalds", "pandas-dev", "scikit-learn", "pytorch", "numpy",
            "microsoft", "google", "facebook", "apache", "django", "psf"]
    repos = ["linux", "pandas", "scikit-learn", "pytorch", "numpy", "vscode",
             "tensorflow", "react", "spark", "django", "cpython"]
    for _ in range(60):
        o, r = rng.choice(orgs), rng.choice(repos)
        kind = rng.choice([
            f"https://github.com/{o}/{r}",
            f"https://github.com/{o}/{r}/blob/main/src/{slug(rng,1,2)}.py",
            f"https://github.com/{o}/{r}/issues/{rng.randint(1,9999)}",
            f"https://github.com/{o}/{r}/pull/{rng.randint(1,9999)}",
            f"https://github.com/{o}/{r}/tree/main/docs/{slug(rng,1,2)}",
        ])
        urls.add(kind)

    # Wikipedia articles.
    for _ in range(60):
        urls.add(f"https://en.wikipedia.org/wiki/{slug(rng,1,3).replace('-', '_').title()}")

    # Stack Overflow questions.
    for _ in range(50):
        urls.add(f"https://stackoverflow.com/questions/{rng.randint(10000,99999999)}/{slug(rng,2,4)}")

    # Documentation sites.
    docs = ["docs.python.org/3/library", "developer.mozilla.org/en-US/docs/Web",
            "docs.djangoproject.com/en/stable", "scikit-learn.org/stable/modules",
            "pandas.pydata.org/docs/reference", "kubernetes.io/docs/concepts",
            "reactjs.org/docs", "docs.aws.amazon.com/AmazonS3/latest/userguide"]
    for _ in range(50):
        urls.add(f"https://{rng.choice(docs)}/{slug(rng,1,3)}.html")

    # E-commerce product pages.
    for _ in range(50):
        site = rng.choice(["amazon.com/dp", "ebay.com/itm", "etsy.com/listing",
                            "walmart.com/ip", "bestbuy.com/site"])
        urls.add(f"https://www.{site}/{rand_id(rng, 10)}")

    # Video / media.
    for _ in range(40):
        urls.add(f"https://www.youtube.com/watch?v={rand_id(rng, 11)}")
    for _ in range(15):
        urls.add(f"https://open.spotify.com/track/{rand_id(rng, 22)}")

    # Social profiles and posts.
    for _ in range(40):
        name = slug(rng, 1, 2)
        site = rng.choice([
            f"https://www.linkedin.com/in/{name}-{rand_id(rng,6).lower()}",
            f"https://twitter.com/{name.replace('-', '')}/status/{rng.randint(10**17, 10**18)}",
            f"https://www.reddit.com/r/{rng.choice(WORDS).replace('-', '')}/comments/{rand_id(rng,6).lower()}/{slug(rng,2,3)}",
            f"https://medium.com/@{name}/{slug(rng,2,4)}-{rand_id(rng,10).lower()}",
        ])
        urls.add(site)

    # Search result pages with query strings.
    for _ in range(40):
        q = slug(rng, 2, 4).replace("-", "+")
        site = rng.choice([
            f"https://www.google.com/search?q={q}&hl=en",
            f"https://duckduckgo.com/?q={q}",
            f"https://www.bing.com/search?q={q}&form=QBLH",
        ])
        urls.add(site)

    return sorted(urls)


def main() -> None:
    rng = random.Random(SEED)
    urls = build(rng)
    OUT.write_text("\n".join(urls) + "\n", encoding="utf-8")
    print(f"Wrote {len(urls)} legitimate deep-link URLs -> {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
