"""
GUI Application for Malicious Website Classifier
Provides a user-friendly interface for URL phishing detection
"""

import threading
import tkinter as tk
from datetime import datetime
from tkinter import scrolledtext, messagebox

from feature_extractor import FeatureExtractor
from phishing_detector import PhishingDetector


class PhishingDetectorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Malicious Website Classifier")
        self.root.geometry("900x700")
        self.root.resizable(True, True)

        # Load model in background
        self.detector = None
        self.loading = True

        # Configure colors
        self.bg_color = "#f0f0f0"
        self.primary_color = "#2c3e50"
        self.danger_color = "#e74c3c"
        self.safe_color = "#27ae60"
        self.warning_color = "#f39c12"

        self.root.configure(bg=self.bg_color)

        self.setup_ui()
        self.load_model()

    def setup_ui(self):
        """Create the user interface"""
        # Title
        title_frame = tk.Frame(self.root, bg=self.primary_color, pady=15)
        title_frame.pack(fill=tk.X)

        title_label = tk.Label(
            title_frame,
            text="🔒 Malicious Website Classifier",
            font=("Helvetica", 20, "bold"),
            bg=self.primary_color,
            fg="white"
        )
        title_label.pack()

        subtitle_label = tk.Label(
            title_frame,
            text="AI-Powered Phishing Detection System",
            font=("Helvetica", 10),
            bg=self.primary_color,
            fg="#ecf0f1"
        )
        subtitle_label.pack()

        # Main container
        main_frame = tk.Frame(self.root, bg=self.bg_color, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Input section
        input_frame = tk.LabelFrame(
            main_frame,
            text="Enter URL to Analyze",
            font=("Helvetica", 12, "bold"),
            bg=self.bg_color,
            padx=10,
            pady=10
        )
        input_frame.pack(fill=tk.X, pady=(0, 10))

        # URL entry
        url_entry_frame = tk.Frame(input_frame, bg=self.bg_color)
        url_entry_frame.pack(fill=tk.X)

        self.url_entry = tk.Entry(
            url_entry_frame,
            font=("Helvetica", 12),
            width=50
        )
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.url_entry.bind('<Return>', lambda e: self.analyze_url())

        self.analyze_btn = tk.Button(
            url_entry_frame,
            text="Analyze",
            command=self.analyze_url,
            font=("Helvetica", 11, "bold"),
            bg=self.primary_color,
            fg="white",
            padx=20,
            pady=8,
            cursor="hand2",
            relief=tk.FLAT
        )
        self.analyze_btn.pack(side=tk.RIGHT)

        # Example URLs
        examples_label = tk.Label(
            input_frame,
            text="Examples: https://google.com  |  http://phishing-site-example.tk",
            font=("Helvetica", 9),
            bg=self.bg_color,
            fg="#7f8c8d"
        )
        examples_label.pack(pady=(5, 0))

        # Results section
        results_frame = tk.LabelFrame(
            main_frame,
            text="Analysis Results",
            font=("Helvetica", 12, "bold"),
            bg=self.bg_color,
            padx=10,
            pady=10
        )
        results_frame.pack(fill=tk.BOTH, expand=True)

        # Result display area
        self.result_text = scrolledtext.ScrolledText(
            results_frame,
            font=("Courier", 10),
            wrap=tk.WORD,
            height=20,
            bg="white",
            relief=tk.SUNKEN,
            borderwidth=2
        )
        self.result_text.pack(fill=tk.BOTH, expand=True)

        # Configure text tags for colored output
        self.result_text.tag_config("title", font=("Helvetica", 14, "bold"))
        self.result_text.tag_config("safe", foreground=self.safe_color, font=("Helvetica", 12, "bold"))
        self.result_text.tag_config("danger", foreground=self.danger_color, font=("Helvetica", 12, "bold"))
        self.result_text.tag_config("warning", foreground=self.warning_color, font=("Helvetica", 11, "bold"))
        self.result_text.tag_config("header", font=("Courier", 10, "bold"))
        self.result_text.tag_config("feature", foreground="#34495e")
        self.result_text.tag_config("timestamp", foreground="#95a5a6", font=("Helvetica", 9))

        # Status bar
        status_frame = tk.Frame(self.root, bg="#34495e", pady=8)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)

        self.status_label = tk.Label(
            status_frame,
            text="Loading model...",
            font=("Helvetica", 9),
            bg="#34495e",
            fg="white"
        )
        self.status_label.pack(side=tk.LEFT, padx=10)

        # Team credits
        credits_label = tk.Label(
            status_frame,
            text="By: Nika Asatiani, Vakhtangi Laluashvili, Khvicha Abramishvili",
            font=("Helvetica", 9),
            bg="#34495e",
            fg="#bdc3c7"
        )
        credits_label.pack(side=tk.RIGHT, padx=10)

        # Initial welcome message
        self.show_welcome_message()

    def show_welcome_message(self):
        """Display welcome message"""
        welcome = """
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║         Welcome to Malicious Website Classifier!                ║
║                                                                  ║
║  This AI-powered tool analyzes URLs to detect phishing sites    ║
║  using behavioral features and deep learning.                   ║
║                                                                  ║
║  → Enter a URL above and click 'Analyze' to begin               ║
║  → The system examines 9 security features                      ║
║  → Results include confidence scores and detailed features      ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝

Waiting for model to load...
"""
        self.result_text.insert(tk.END, welcome)
        self.result_text.config(state=tk.DISABLED)

    def load_model(self):
        """Load the trained model in background"""

        def load():
            try:
                self.detector = PhishingDetector.load()
                self.loading = False
                self.root.after(0, self.on_model_loaded)
            except Exception as e:
                self.root.after(0, lambda: self.on_model_error(str(e)))

        thread = threading.Thread(target=load, daemon=True)
        thread.start()

    def on_model_loaded(self):
        """Called when model is successfully loaded"""
        self.status_label.config(text="✓ Model loaded successfully - Ready to analyze URLs")
        self.analyze_btn.config(state=tk.NORMAL)

        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)

        ready_msg = """
╔══════════════════════════════════════════════════════════════════╗
║                      ✓ System Ready                             ║
╚══════════════════════════════════════════════════════════════════╝

Model loaded successfully!
You can now analyze URLs for phishing detection.

Enter a URL above and press 'Analyze' or hit Enter.
"""
        self.result_text.insert(tk.END, ready_msg, "safe")
        self.result_text.config(state=tk.DISABLED)
        self.url_entry.focus()

    def on_model_error(self, error_msg):
        """Called when model fails to load"""
        self.status_label.config(text="✗ Error loading model")
        messagebox.showerror(
            "Model Error",
            f"Failed to load model:\n{error_msg}\n\nPlease run 'python train.py' first."
        )

    def analyze_url(self):
        """Analyze the entered URL"""
        if self.loading:
            messagebox.showwarning("Please Wait", "Model is still loading...")
            return

        url = self.url_entry.get().strip()

        if not url:
            messagebox.showwarning("Empty URL", "Please enter a URL to analyze")
            return

        # Add http:// if no scheme
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        # Disable button during analysis
        self.analyze_btn.config(state=tk.DISABLED, text="Analyzing...")
        self.status_label.config(text="Analyzing URL...")

        # Run analysis in background thread
        thread = threading.Thread(
            target=self.perform_analysis,
            args=(url,),
            daemon=True
        )
        thread.start()

    def perform_analysis(self, url):
        """Perform the actual analysis in background"""
        try:
            # Get features
            features = FeatureExtractor.extract(url)
            feat_dict = features.iloc[0].to_dict()

            # Predict
            labels, probs = self.detector.predict(features)
            prediction = "PHISHING" if labels[0] == 1 else "LEGITIMATE"
            confidence = probs[0].max()
            prob_legit = probs[0][0]
            prob_phish = probs[0][1]

            # Update UI in main thread
            self.root.after(0, lambda: self.display_results(
                url, prediction, confidence, prob_legit, prob_phish, feat_dict
            ))

        except Exception as e:
            self.root.after(0, lambda: self.display_error(url, str(e)))

    def display_results(self, url, prediction, confidence, prob_legit, prob_phish, features):
        """Display analysis results"""
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Header
        self.result_text.insert(tk.END, "═" * 80 + "\n")
        self.result_text.insert(tk.END, f"  URL ANALYSIS REPORT\n", "title")
        self.result_text.insert(tk.END, "═" * 80 + "\n\n")

        self.result_text.insert(tk.END, f"URL: {url}\n", "header")
        self.result_text.insert(tk.END, f"Timestamp: {timestamp}\n\n", "timestamp")

        # Prediction result
        self.result_text.insert(tk.END, "─" * 80 + "\n")
        self.result_text.insert(tk.END, "PREDICTION RESULT\n", "header")
        self.result_text.insert(tk.END, "─" * 80 + "\n\n")

        if prediction == "LEGITIMATE":
            self.result_text.insert(tk.END, f"✓ {prediction}\n", "safe")
            emoji = "✓"
            interpretation = "This website appears to be SAFE based on behavioral analysis."
        else:
            self.result_text.insert(tk.END, f"⚠ {prediction}\n", "danger")
            emoji = "⚠"
            interpretation = "This website shows SUSPICIOUS patterns and may be a phishing attempt!"

        self.result_text.insert(tk.END, f"\nConfidence: {confidence:.1%}\n", "warning")
        self.result_text.insert(tk.END, f"Interpretation: {interpretation}\n\n")

        # Probability breakdown
        self.result_text.insert(tk.END, "Probability Breakdown:\n", "header")
        self.result_text.insert(tk.END, f"  • Legitimate: {prob_legit:.1%}\n")
        self.result_text.insert(tk.END, f"  • Phishing:   {prob_phish:.1%}\n\n")

        # Feature analysis
        self.result_text.insert(tk.END, "─" * 80 + "\n")
        self.result_text.insert(tk.END, "FEATURE ANALYSIS (9 Security Indicators)\n", "header")
        self.result_text.insert(tk.END, "─" * 80 + "\n\n")

        feature_descriptions = {
            'having_IP_Address': ('IP Address Usage',
                                  {1: '✓ Uses domain name', -1: '✗ Uses IP address'}),
            'URL_Length': ('URL Length',
                           {1: '✓ Short (<54 chars)', 0: '○ Medium (54-75)', -1: '✗ Long (>75)'}),
            'SSLfinal_State': ('SSL Certificate',
                               {1: '✓ Valid HTTPS', 0: '○ Invalid cert', -1: '✗ No HTTPS'}),
            'SFH': ('Form Handler',
                    {1: '✓ Safe (same domain)', 0: '○ Suspicious', -1: '✗ External/empty'}),
            'popUpWindow': ('Popup Windows',
                            {1: '✓ No suspicious popups', 0: '○ Unknown', -1: '✗ Suspicious JS detected'}),
            'Request_URL': ('External Resources',
                            {1: '✓ Same-domain resources', 0: '○ Mixed', -1: '✗ Many external'}),
            'URL_of_Anchor': ('Link Anchors',
                              {1: '✓ Internal links', 0: '○ Mixed', -1: '✗ Many external'}),
            'web_traffic': ('Web Traffic',
                            {1: '✓ Site responds normally', 0: '○ Unknown'}),
            'age_of_domain': ('Domain Age',
                              {1: '✓ Established (>1 year)', 0: '○ New/Unknown', -1: '✗ Very new'})
        }

        for feat_name, feat_val in features.items():
            if feat_name in feature_descriptions:
                desc, values_map = feature_descriptions[feat_name]
                status = values_map.get(feat_val, f'Value: {feat_val}')

                self.result_text.insert(tk.END, f"{desc:20s}: ", "feature")

                if feat_val == 1:
                    self.result_text.insert(tk.END, f"{status}\n", "safe")
                elif feat_val == -1:
                    self.result_text.insert(tk.END, f"{status}\n", "danger")
                else:
                    self.result_text.insert(tk.END, f"{status}\n", "warning")

        # Recommendation
        self.result_text.insert(tk.END, "\n" + "─" * 80 + "\n")
        self.result_text.insert(tk.END, "RECOMMENDATION\n", "header")
        self.result_text.insert(tk.END, "─" * 80 + "\n\n")

        if prediction == "LEGITIMATE":
            recommendation = """✓ This website appears safe based on our analysis.
  However, always exercise caution:
  • Verify the URL matches the intended website
  • Check for HTTPS before entering sensitive data
  • Be wary of unsolicited links in emails"""
        else:
            recommendation = """⚠ WARNING: This website shows phishing characteristics!
  Recommended actions:
  • DO NOT enter personal information or credentials
  • DO NOT download files from this site
  • Verify the legitimate URL of the service
  • Report this site if it's impersonating a known brand"""

        if prediction == "LEGITIMATE":
            self.result_text.insert(tk.END, recommendation + "\n", "safe")
        else:
            self.result_text.insert(tk.END, recommendation + "\n", "danger")

        self.result_text.insert(tk.END, "\n" + "═" * 80 + "\n")

        self.result_text.config(state=tk.DISABLED)

        # Re-enable button
        self.analyze_btn.config(state=tk.NORMAL, text="Analyze")
        self.status_label.config(text=f"✓ Analysis complete - {prediction}")

    def display_error(self, url, error_msg):
        """Display error message"""
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)

        self.result_text.insert(tk.END, "═" * 80 + "\n")
        self.result_text.insert(tk.END, "  ERROR\n", "danger")
        self.result_text.insert(tk.END, "═" * 80 + "\n\n")

        self.result_text.insert(tk.END, f"URL: {url}\n\n", "header")
        self.result_text.insert(tk.END, "Failed to analyze URL.\n\n", "danger")
        self.result_text.insert(tk.END, f"Error details:\n{error_msg}\n\n")
        self.result_text.insert(tk.END, "Possible reasons:\n")
        self.result_text.insert(tk.END, "  • URL is not accessible\n")
        self.result_text.insert(tk.END, "  • Network connection issues\n")
        self.result_text.insert(tk.END, "  • Invalid URL format\n")
        self.result_text.insert(tk.END, "  • Site blocks automated requests\n\n")

        self.result_text.config(state=tk.DISABLED)

        self.analyze_btn.config(state=tk.NORMAL, text="Analyze")
        self.status_label.config(text="✗ Analysis failed")


def main():
    """Main entry point"""
    root = tk.Tk()
    app = PhishingDetectorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
