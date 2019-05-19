package cz.blackchameleon.pcaphandler

import android.content.*
import android.net.*
import android.webkit.*
import android.widget.*
import androidx.core.content.*
import io.pkts.*
import io.pkts.packet.impl.*
import io.pkts.protocol.*
import java.io.*

/**
 * FileEngine
 * Handles all computation for stored files info.
 *
 * @author Karolina Klepackova <klepackova.karolina@email.cz>
 * @since ver 1.1
 */

class FileEngine : FileProvider() {

  /**
   * Is invoked when user chooses a file to be opened.
   */
  fun handleOnFileClick(absolutePath: String?, context: Context?) {
    if (absolutePath == null) {
      Toast.makeText(context, "Sorry. This file doesn\'t exist.", Toast.LENGTH_SHORT).show()
      return
    }

    val suffix = absolutePath.substringAfterLast(".")

    // Decides what to do depending on file's suffix.
    when (suffix) {
      "pcap" -> makeTxtFile(absolutePath)
      "txt" -> openFile(absolutePath, context)
      else -> openFile(absolutePath, context)
    }
  }

  /**
   * Makes readable text file containing each packet's info from pcap file.
   */
  private fun makeTxtFile(absolutePath: String) {
    val txtFilePath = absolutePath.replaceAfterLast(".", "txt")
    val txtFile = File(txtFilePath)
    val pcap: Pcap

    // Creates stream from pcap file.
    try {
      pcap = Pcap.openStream(absolutePath)
    } catch (e: Exception) {
      e.printStackTrace()
      return
    }

    // Iterates through whole file.
    pcap.loop {
      var string = ""

      if (it.hasProtocol(Protocol.TCP)) {
        val packet = it.getPacket(Protocol.TCP)
        string += "Arrival time: " + it.arrivalTime.toString() + "\n"
        string += "Protocol: " + it.protocol.toString() + "\n"
        if (packet is TcpPacketImpl) {
          string += "Destination port: " + packet.destinationPort.toString() + "\n"
          string += "Header length: " + packet.headerLength.toString() + "\n"
          string += "Source port: " + packet.sourcePort.toString() + "\n"
          string += "Ack number: " + packet.acknowledgementNumber.toString() + "\n"
          string += "Name: " + packet.name.toString() + "\n"
          string += "Sequence number: " + packet.sequenceNumber.toString() + "\n"
        }

        if (packet.hasProtocol(Protocol.IPv4)) {
          val ipv4 = packet.getPacket(Protocol.IPv4)
          string += ipv4.arrivalTime.toString()
          string += ipv4.protocol
        } else if (packet.hasProtocol(Protocol.IPv6)) {
          val ipv6 = packet.getPacket(Protocol.IPv6)
          string += ipv6.arrivalTime.toString()
          string += ipv6.protocol
        }
      }

      txtFile.writeText(string)
      true
    }
  }

  /**
   * Opens file via 3rd party app. Used for unsupported file formats.
   */
  private fun openFile(absolutePath: String, context: Context?) {
    val type = getMimeFileType(absolutePath)
    val data = Uri.parse("content://$absolutePath")
    val intent = Intent()
    intent.action = Intent.ACTION_VIEW
    intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    intent.setDataAndType(data, type)
    context?.startActivity(intent)
  }

  /**
   * Returns mime type of file. Necessary for decision which 3rd party apps should be listed.
   *
   * @return Mime type of file in string.
   */
  private fun getMimeFileType(url: String): String? {
    var type: String? = null
    val extension = MimeTypeMap.getFileExtensionFromUrl(url)
    if (extension != null) {
      type = MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension)
    }
    return type
  }
}