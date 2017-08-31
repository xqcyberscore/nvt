###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for ax25-tools FEDORA-2015-6464
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.869614");
  script_version("$Revision: 6630 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:34:32 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2015-07-07 06:28:12 +0200 (Tue, 07 Jul 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for ax25-tools FEDORA-2015-6464");
  script_tag(name: "summary", value: "Check the version of ax25-tools");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "ax25-tools is a collection of tools that
are used to configure an ax.25 enabled computer. They will configure interfaces
and assign callsigns to ports as well as Net/ROM and ROSE configuration. This
package only contains the command line programs  the GUI programs are contained
in ax25-tools-x package.

 * m6pack - handle multiple 6pack TNCs on a single interface
 * ax25d - general purpose AX.25, NET/ROM and Rose daemon
 * axctl - configure/Kill running AX.25 connections
 * axparms - configure AX.25 interfaces
 * axspawn - allow automatic login to a Linux system
 * beacon - transmit periodic messages on an AX.25 port
 * bpqparms - configure BPQ ethernet devices
 * mheardd - display AX.25 calls recently heard
 * rxecho - transparently route AX.25 packets between ports
 * mheard - collect information about packet activity
 * dmascc_cfg - configure dmascc devices
 * sethdlc - get/set Linux HDLC packet radio modem driver port information
 * smmixer - get/set Linux soundcard packet radio modem driver mixer
 * kissattach - Attach a KISS or 6PACK interface
 * kissnetd - create a virtual network
 * kissparms - configure KISS TNCs
 * mkiss - attach multiple KISS interfaces
 * net2kiss - convert a network AX.25 driver to a KISS stream on a pty
 * netromd - send and receive NET/ROM routing messages
 * nodesave - saves NET/ROM routing information
 * nrattach - start a NET/ROM interface
 * nrparms - configure a NET/ROM interface
 * nrsdrv - KISS to NET/ROM serial converter
 * rsattach - start a ROSE interface
 * rsdwnlnk - user exit from the ROSE network
 * rsmemsiz - monitor the ROSE subsystem
 * rsusers.sh - monitor AX.25, NET/ROM and ROSE users
 * rsparms - configure a ROSE interface
 * rsuplnk - User entry into the ROSE network
 * rip98d - RIP98 routing daemon
 * ttylinkd - TTYlink daemon for AX.25, NET/ROM, ROSE and IP
 * ax25_call - Make an AX.25 connection
 * netrom_call - Make a NET/ROM connection
 * rose_call - Make a ROSE connection
 * tcp_call - Make a TCP connection
 * yamcfg - configure a YAM interface
");
  script_tag(name: "affected", value: "ax25-tools on Fedora 22");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "FEDORA", value: "2015-6464");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2015-April/156244.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC22")
{

  if ((res = isrpmvuln(pkg:"ax25-tools", rpm:"ax25-tools~0.0.10~0.12.rc2.fc22", rls:"FC22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
