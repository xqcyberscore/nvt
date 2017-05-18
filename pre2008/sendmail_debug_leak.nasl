# OpenVAS Vulnerability Test
# $Id: sendmail_debug_leak.nasl 6053 2017-05-01 09:02:51Z teissa $
# Description: Sendmail debug mode leak
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

# References:
# From: "Michal Zalewski" <lcamtuf@echelon.pl>
# To: bugtraq@securityfocus.com
# CC: sendmail-security@sendmail.org
# Subject: RAZOR advisory: multiple Sendmail vulnerabilities

CPE = 'cpe:/a:sendmail:sendmail';

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11088");
 script_version("$Revision: 6053 $");
 script_tag(name:"last_modification", value:"$Date: 2017-05-01 11:02:51 +0200 (Mon, 01 May 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3898);
 script_cve_id("CVE-2001-0715");
 script_tag(name:"cvss_base", value:"2.1");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
 script_name("Sendmail debug mode leak");
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 script_family("SMTP problems");
 script_dependencies("gb_sendmail_detect.nasl");
 script_require_keys("SMTP/sendmail");
 script_require_ports("Services/smtp", 25, 465, 587);

 script_tag(name:"solution", value:"upgrade to the latest version of Sendmail or
 do not allow users to process the queue (RestrictQRun option)
 Note : This vulnerability is _local_ only");
 script_tag(name:"summary", value:"According to the version number of the remote mail server, 
 a local user may be able to obtain the complete mail configuration
 and other interesting information about the mail queue even if
 he is not allowed to access those information directly, by running
	sendmail -q -d0-nnnn.xxx
 where nnnn & xxx are debugging levels.

 If users are not allowed to process the queue (which is the default)
 then you are not vulnerable.");

 script_tag(name:"solution_type", value:"VendorFix");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");

 exit(0);
}

#

include("smtp_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);

banner = get_smtp_banner(port: port);
if(! banner || "Switch-" >< banner ) exit(0);

if(egrep(pattern:".*Sendmail.*8\.(([0-9]\..*)|(1[01]\..*)|(12\.0)).*",
	string:banner)) {
  security_message(port:port);
  exit(0);
}

exit(99);