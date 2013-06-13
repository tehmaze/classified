# Python imports
import datetime
import os
import smtplib
import sys
from email.mime.text import MIMEText

# Project imports
from classified.report.html import HTMLReport


class MailReport(HTMLReport):
    name = 'mail'
    sender = '{user}@{hostname}'
    subject = 'Classified report for {fqdn}'

    def setup(self):
        if not self.option.output:
            print >>sys.stderr, 'Please supply recipients with --output'
            sys.exit(1)

        # Setup template environment
        self.setup_env()

    def render(self):
        self.entries['user'] = os.environ.get('USER', 'no-reply')
        self.entries['time']['finish'] = datetime.datetime.now()

        subject = self.config.getdefault('report:mail', 'subject',
                                         self.subject)
        sender = self.config.getdefault('report:mail', 'sender',
                                        self.sender)

        # Compile MIME message
        message = MIMEText(self.template.render(**self.entries))
        message['Subject'] = subject.format(**self.entries)
        message['From'] = sender.format(**self.entries)
        message['To'] = self.option.output
        message['X-Mailer'] = 'classified/1.0'

        print message.as_string()

        # Send mail
        smtp = smtplib.SMTP(self.config.getdefault('report:mail',
                                                   'server',
                                                   'localhost'))
        smtp.set_debuglevel(9)
        smtp.sendmail(sender.format(**self.entries),
                      self.option.output.split(','),
                      message.as_string())
        try:
            smtp.quit()
        except:
            pass
