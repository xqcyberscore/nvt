# OpenVAS Vulnerability Test
# $Id: sendmail_parsing_redirection.nasl 6040 2017-04-27 09:02:38Z teissa $
# Description: Sendmail Parsing Redirection DOS
#
# Authors:
# Xue Yong Zhi <xueyong@udel.edu>
#
# Copyright:
# Copyright (C) 2003 Xue Yong Zhi
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

CPE = 'cpe:/a:sendmail:sendmail';

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11352");
 script_version("$Revision: 6040 $");
 script_tag(name:"last_modification", value:"$Date: 2017-04-27 11:02:38 +0200 (Thu, 27 Apr 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(8674);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-1999-0393");
 #No bugtraq_id;
 script_name("Sendmail Parsing Redirection DOS");
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2003 Xue Yong Zhi");
 script_family("SMTP problems");
 script_dependencies("gb_sendmail_detect.nasl");
 script_require_keys("SMTP/sendmail");
 script_require_ports("Services/smtp", 25, 465, 587);

 script_tag(name:"solution", value:"Install sendmail newer than 8.9.3 or install a vendor
 supplied patch.");
 script_tag(name:"summary", value:"The remote sendmail server, according to its version number,
 allows remote attackers cause a denial of service by sending messages with a large number of headers.");

 script_tag(name:"solution_type", value:"VendorFix");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");

 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);

banner = get_smtp_banner(port:port);

if(banner)
{
 #looking for Sendmail 8.8.*, 8.9.2
 if(egrep(pattern:".*sendmail[^0-9]*((8\.(8|8\.[0-9]+|9\.2))|SMI-8\.)/.*", string:banner, icase:TRUE)) {
    security_message(port:port);
    exit(0);
 }
}

exit(99);