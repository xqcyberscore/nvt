# OpenVAS Vulnerability Test
# $Id: sendmail_forword_include.nasl 6046 2017-04-28 09:02:54Z teissa $
# Description: Sendmail Group Permissions Vulnerability
#
# Authors:
# Xue Yong Zhi <xueyong@udel.edu>
#
# Copyright:
# Copyright (C) 2001 Xue Yong Zhi
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
 script_oid("1.3.6.1.4.1.25623.1.0.11349");
 script_version("$Revision: 6046 $");
 script_tag(name:"last_modification", value:"$Date: 2017-04-28 11:02:54 +0200 (Fri, 28 Apr 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(715);
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-1999-0129");
 script_name("Sendmail Group Permissions Vulnerability");
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2001 Xue Yong Zhi");
 script_family("SMTP problems");
 script_dependencies("gb_sendmail_detect.nasl");
 script_require_keys("SMTP/sendmail");
 script_require_ports("Services/smtp", 25, 465, 587);

 script_tag(name:"solution", value:"Install sendmail newer than 8.8.4 or install a vendor
 supplied patch.");
 script_tag(name:"summary", value:"The remote sendmail server, according to its version number,
 allows local users to write to a file and gain group permissions via a .forward or :include: file.");

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
 #looking for Sendmail 8.8, 8.8.1-8.8.3
 if(egrep(pattern:".*sendmail[^0-9]*8\.(8|8\.[1-3])/.*", string:banner, icase:TRUE)) {
    security_message(port:port);
    exit(0);
 }
}

exit(99);