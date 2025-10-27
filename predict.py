import sys

from phishing_detector import PhishingDetector

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python predict.py <url1> <url2> ...")
        sys.exit(1)

    detector = PhishingDetector.load()
    urls = sys.argv[1:]
    results = detector.predict_urls(urls)

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for r in results:
        if 'error' in r:
            print(f"{r['url']}: ERROR - {r['error']}")
        else:
            print(f"{r['url']}: {r['prediction']} ({r['confidence']:.1%})")
