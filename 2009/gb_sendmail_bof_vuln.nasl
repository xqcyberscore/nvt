###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sendmail_bof_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Sendmail Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation will let the remote attacker to create the mangled
  message by execute arbitrary code, and can cause application crash.";
tag_affected = "Sendmail Version prior 8.13.2";
tag_insight = "Buffer overflow error is due to improper handling of long X- header.";
tag_solution = "Upgrade to version 8.13.2 or later
  http://www.sendmail.org/releases";
tag_summary = "The host is running Sendmail and is prone to Buffer Overflow Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800609");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-05-13 10:01:19 +0200 (Wed, 13 May 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1490");
  script_name("Sendmail Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://www.sendmail.org/releases/8.13.2");
  script_xref(name : "URL" , value : "http://www.nmrc.org/~thegnome/blog/apr09");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_sendmail_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

sendmailPort = get_kb_item("Services/smtp");

if(!sendmailPort){
  exit(0);
}

sendmailVer = get_kb_item("SMTP/" + sendmailPort + "/Sendmail");

if(sendmailVer != NULL)
{
  if(version_is_less(version:sendmailVer, test_version:"8.13.2")){
    security_message(sendmailPort);
  }
}
