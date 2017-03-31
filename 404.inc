###############################################################################
# Include to provide common error messages interpreted as a 404 
# $Id: 404.inc 4213 2016-10-05 09:30:52Z cfi $
#
# Authors:
# Extracted from no404.nasl and DDI_Directory_Scanner.nasl
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software
# Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
# $Revision: 4213 $
#
###############################################################################

errmessages_404 = make_list(
"not found", # TBD: too generic?
"404", # TBD: too generic?
"error has occurred",
"FireWall-1 message",
"Reload acp_userinfo database",
"IMail Server Web Messaging",
"HP Web JetAdmin",
"Error processing SSI file",
"ExtendNet DX Configuration",
"Unable to complete your request due to added security features",
"Client Authentication Remote Service</font>",
"Bad Request",
"<form action=/session_login.cgi",	# webmin
"Webmin server",
"Management Console",
"TYPE=password",	# As in "<input type=password>"
"The userid or password that was specified is not valid.",  # Tivoli server administrator
"Access Failed",
"Please identify yourself:",
"forcelogon.htm",
"encountered an error while publishing this resource",
"No web site is configured at this address",
"No website is configured at this address",
'name=qt id="search" size=40 value=" "',
"PHP Fatal error:  Unable to open",
"RSA SecurID User Name Request",
"Error Occurred While Processing Request",
"Web access denied",
"Error Page",
"The page you requested doesn't exist",
"TYPE='password'",
'TYPE="password"',
"This version of Compaq's management software has added",
"Error - Bad Request",
"Insufficient Access",
"The userid or password that was specified is not valid",
"Content-Length: 0" );

global_var errmessges_404;

# Previously in DDI_Directory_Scanner.nasl but not added yet
# TBD: too generic?
# errmsg[ei++] = "unknown";