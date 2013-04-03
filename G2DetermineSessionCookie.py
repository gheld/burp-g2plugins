"""
G2DetermineSessionCookie

:copyright: (c) 2013 by Garrett Held.

"""

from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from burp import IParameter

from java.io import PrintWriter
from javax.swing import JMenuItem

from java.awt import Dimension
from javax.swing import Box
from javax.swing import BoxLayout
from javax.swing import JFrame
from javax.swing import JPanel

from javax.swing import JButton
from javax.swing import JProgressBar
from javax.swing import JTextArea
from javax.swing import JScrollPane

from org.python.core.util import StringUtil
from difflib import SequenceMatcher
import threading

cancelThread = False

def httpresponse_bytes_diffratio(helpers, http_bytes_one, http_bytes_two):
    """ Returns a difference ratio between two byte arrays each representing
        one http response. Ratio=1.0 is a perfect match.
    """
    http_one_info = helpers.analyzeResponse(http_bytes_one)
    http_one = StringUtil.fromBytes(http_bytes_one)
    http_one_body = http_one[http_one_info.getBodyOffset():]

    http_two_info = helpers.analyzeResponse(http_bytes_two)
    http_two = StringUtil.fromBytes(http_bytes_two)
    http_two_body = http_two[http_two_info.getBodyOffset():]

    s = SequenceMatcher(lambda x: x== " ", http_one_body, http_two_body)
    return s.ratio()

class ThreadDetermineCookie(threading.Thread):
    """ Thread class to control the submission of the requests that
        are needed to determine which session cookie will be used.
    """

    def __init__(self, callbacks, selected_message, statusTextArea, progressBar):
        threading.Thread.__init__(self)
        self.callbacks = callbacks
        self.selected_message = selected_message
        self.statusTextArea = statusTextArea
        self.progressBar = progressBar

    def run(self):
        """
        Where all the work is done.
        Three steps
        1) Make the request again to make sure it's stable (We use python difflib)
        2) Make the request without any cookies, if it's similar the cookies aren't required
        3) Loop through removing one cookie at a time, if the diff isn't big we leave it out, if 
           it is we can figure that it's required and we leave it in

        At the end we're left with the required cookies.
        """
        selected_message = self.selected_message

        original_request_bytes = selected_message.getRequest()
        original_request = StringUtil.fromBytes(original_request_bytes)
        original_response_bytes = selected_message.getResponse()
        original_response = StringUtil.fromBytes(original_response_bytes)

        http_service = selected_message.getHttpService()

        helpers = self.callbacks.getHelpers()
        request_info = helpers.analyzeRequest(http_service, original_request_bytes)

        parameters = request_info.getParameters();
        cookie_parameters = [parameter for parameter in parameters if parameter.getType() == IParameter.PARAM_COOKIE]

        num_requests_needed = len(cookie_parameters) + 2
        num_requests_made = 0

        self.progressBar.setMaximum(num_requests_needed)
        self.progressBar.setValue(num_requests_made)

        #===========================================================
        # We will resubmit the request to make sure it is somewhat stable
        self.statusTextArea.append("Making baseline request which we will compare to original request (1 of 1)")
        self.statusTextArea.append("\n")
        baseline_reqres_pair = self.callbacks.makeHttpRequest(http_service, original_request)
        threshold = httpresponse_bytes_diffratio(helpers, original_response_bytes, baseline_reqres_pair.getResponse())
        if (threshold < 0.6):
            self.statusTextArea.append("ERROR: Not a stable HTTP request, try another where it's nearly the same every request")
            self.statusTextArea.append("\n")
            self.progressBar.setValue(num_requests_needed)
            return
        # Pad it a little by decreasing the threshold...
        threshold = threshold * 0.8 #TODO: We should automate discovering the right threshold
        self.statusTextArea.append("...Complete, threshold ratio is %s" % (threshold))
        self.statusTextArea.append("\n")
        #===========================================================

        if (cancelThread is True):
            print "Canceled"
            return

        num_requests_made = num_requests_made + 1
        self.progressBar.setValue(num_requests_made)

        #===========================================================
        # Now we'll check if it actually requires authentication by removing all cookies
        nocookies_request_bytes = StringUtil.toBytes(original_request)
        for parameter in cookie_parameters:
            nocookies_request_bytes = helpers.removeParameter(nocookies_request_bytes, parameter)
        self.statusTextArea.append("Making no-cookie request to make sure it requires them (1 of 1)")
        self.statusTextArea.append("\n")
        nocookie_reqres_pair = self.callbacks.makeHttpRequest(http_service, nocookies_request_bytes)
        nocookiediff = httpresponse_bytes_diffratio(helpers, original_response_bytes, nocookie_reqres_pair.getResponse())
        if (nocookiediff > threshold):
            self.statusTextArea.append("ERROR: Cookies don't seem to be required or it's too close to tell")
            self.statusTextArea.append("\n")
            self.progressBar.setValue(num_requests_needed)
            return
        self.statusTextArea.append("...Complete, confirmed at least one cookie is required")
        self.statusTextArea.append("\n")

        #===========================================================

        if (cancelThread is True):
            print "Canceled"
            return

        num_requests_made = num_requests_made + 1
        self.progressBar.setValue(num_requests_made)

        #===========================================================
        # Now iterate over all the cookie values, removing one at a time until left with required ones
        self.statusTextArea.append("Making requests, removing each cookie one at a time. (%d requests)" % (len(cookie_parameters)))
        self.statusTextArea.append("\n")

        minimumcookies_request_bytes = StringUtil.toBytes(original_request)
        for parameter in cookie_parameters:
            if (cancelThread is True):
                print "Canceled"
                return
            missingcookie_request_bytes = helpers.removeParameter(minimumcookies_request_bytes, parameter)
            missingcookie_reqres_pair = self.callbacks.makeHttpRequest(http_service, missingcookie_request_bytes)
            missingcookiediff = httpresponse_bytes_diffratio(helpers, original_response_bytes, missingcookie_reqres_pair.getResponse())
            if (missingcookiediff > threshold):
                self.statusTextArea.append("  Cookie '%s' is not required (%s similarity ratio)" % (parameter.getName(), missingcookiediff))
                self.statusTextArea.append("\n")
                minimumcookies_request_bytes = missingcookie_request_bytes
            else:
                self.statusTextArea.append("* Cookie '%s' is required (%s similarity ratio)" % (parameter.getName(), missingcookiediff))
                self.statusTextArea.append("\n")
            num_requests_made = num_requests_made + 1
            self.progressBar.setValue(num_requests_made)

        #===========================================================

        #===========================================================
        # minimumcookies_request_bytes now contains a request with the minimum number
        #  of cookies needed to maintain the session.
        #===========================================================
        # Display the results
        self.statusTextArea.append("== Required Cookies ==")
        self.statusTextArea.append("\n")

        mininumcookies_request_info = helpers.analyzeRequest(http_service, minimumcookies_request_bytes)
        minimum_cookie_parameters = [parameter for parameter in mininumcookies_request_info.getParameters() if parameter.getType() == IParameter.PARAM_COOKIE]
        for cookie_parameter in minimum_cookie_parameters:
            self.statusTextArea.append(cookie_parameter.getName())
            self.statusTextArea.append("\n")
        #===========================================================
        return

class DetermineCookieFrame(JFrame):
    """ This is the GUI for for the user to control the actions when
        determining which cookie is the session cookie.
    """

    def __init__(self, callbacks, selected_message):
        super(DetermineCookieFrame, self).__init__()
        self.callbacks = callbacks
        self.selected_message = selected_message
        self.windowClosing = self.close

    def loadPanel(self):
        panel = JPanel()

        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))

        bottomButtonBarPanel = JPanel()
        bottomButtonBarPanel.setLayout(BoxLayout(bottomButtonBarPanel, BoxLayout.X_AXIS))
        bottomButtonBarPanel.setAlignmentX(1.0)

        self.runButton = JButton("Run", actionPerformed=self.start)
        self.cancelButton = JButton("Close", actionPerformed=self.cancel)

        bottomButtonBarPanel.add(Box.createHorizontalGlue());
        bottomButtonBarPanel.add(self.runButton)
        bottomButtonBarPanel.add(self.cancelButton)

        # Dimension(width,height)    
        bottom = JPanel()
        bottom.setLayout(BoxLayout(bottom, BoxLayout.X_AXIS))
        bottom.setAlignmentX(1.0)

        self.progressBar = JProgressBar()
        self.progressBar.setIndeterminate(False)
        self.progressBar.setMaximum(100)
        self.progressBar.setValue(0)

        bottom.add(self.progressBar)

        self.statusTextArea = JTextArea()
        self.statusTextArea.setEditable(False)
        scrollPane = JScrollPane(self.statusTextArea)
        scrollPanel = JPanel()
        scrollPanel.setLayout(BoxLayout(scrollPanel, BoxLayout.X_AXIS))
        scrollPanel.setAlignmentX(1.0)
        scrollPanel.add(scrollPane)

        panel.add(scrollPanel)
        panel.add(bottomButtonBarPanel)
        panel.add(bottom)

        self.add(panel)
        self.setTitle("Determine Session Cookie(s)")
        self.setSize(450, 300)
        self.setLocationRelativeTo(None)
        self.setVisible(True)


        original_request_bytes = self.selected_message.getRequest()
        http_service = self.selected_message.getHttpService()
        helpers = self.callbacks.getHelpers()
        request_info = helpers.analyzeRequest(http_service, original_request_bytes)
        parameters = request_info.getParameters();
        cookie_parameters = [parameter for parameter in parameters if parameter.getType() == IParameter.PARAM_COOKIE]
        num_requests_needed = len(cookie_parameters) + 2
        self.statusTextArea.append("This may require up to " + str(num_requests_needed) + " requests to be made. Hit 'Run' to begin.\n")

    def start(self, event):
        global cancelThread
        cancelThread = False
        self.runButton.setEnabled(False)
        self.cancelButton.setText("Cancel")
        thread = ThreadDetermineCookie(self.callbacks, self.selected_message, self.statusTextArea, self.progressBar)
        thread.start()

    def cancel(self, event):
        self.setVisible(False);
        self.dispose();

    def close(self, event):
        global cancelThread
        cancelThread = True

class BurpExtender(IBurpExtender):
    """ Registers the callback for the menu which will be defined
        in DetermineCookieMenuItem
    """

    def	registerExtenderCallbacks(self, callbacks):
        # set our extension name
        callbacks.setExtensionName("G2 Determine Session Cookie")
        callbacks.registerContextMenuFactory(DetermineCookieMenuItem(callbacks))

        # obtain our output and error streams
        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)
        
        # write a message to our output stream
        stdout.println("G2 Determine Session Cookie - Successful Initialization")


class DetermineCookieMenuItem(IContextMenuFactory):
    """ Defines when the menu item is shown (on a history request/response) and
        the action that's triggered.
    """

    def __init__(self, callbacks):
        self.callbacks = callbacks

    def createMenuItems(self, invocation):

        itemlabel = 'Use to determine Session Cookie(s)'
        stdout = PrintWriter(self.callbacks.getStdout(), True)

        def determineSessionCookie(event):
            selected_messages = invocation.getSelectedMessages()
            selected_message = selected_messages[0]
            determine_cookie_frame = DetermineCookieFrame(self.callbacks, selected_message)
            determine_cookie_frame.loadPanel()

        if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_PROXY_HISTORY):
            if len(invocation.getSelectedMessages()) == 1:
                jitem = JMenuItem(itemlabel, actionPerformed=determineSessionCookie)
                return [jitem,]



            