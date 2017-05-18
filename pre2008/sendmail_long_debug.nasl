# OpenVAS Vulnerability Test
# $Id: sendmail_long_debug.nasl 6040 2017-04-27 09:02:38Z teissa $
# Description: Sendmail long debug local overflow
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
 script_oid("1.3.6.1.4.1.25623.1.0.11348");
 script_version("$Revision: 6040 $");
 script_tag(name:"last_modification", value:"$Date: 2017-04-27 11:02:38 +0200 (Thu, 27 Apr 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-1999-1309");
 #NO bugtraq_id
 script_name("Sendmail long debug local overflow");
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2003 Xue Yong Zhi");
 script_family("SMTP problems");
 script_dependencies("gb_sendmail_detect.nasl");
 script_require_keys("SMTP/sendmail");
 script_require_ports("Services/smtp", 25, 465, 587);

 script_tag(name:"solution", value:"Install sendmail newer than versions 8.6.8 or install
 a vendor supplied patch.");
 script_tag(name:"summary", value:"The remote sendmail server, according to its version number,
 allows local users to gain root access via a large value in the debug (-d) command line option");

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
 #looking for Sendmail 8.6.7 and previous
 if(egrep(pattern:".*sendmail[^0-9]*(SMI-)?8\.([0-5]|[0-5]\.[0-9]+|6|6\.[0-7])/.*", string:banner, icase:TRUE)) {
    security_message(port:port);
    exit(0);
 }
}

exit(99);