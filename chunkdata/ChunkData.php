<?php
// @@protoc_insertion_point(namespace:.ChunkData)

/**
 * Generated by the protocol buffer compiler.  DO NOT EDIT!
 * source: chunk.proto
 *
 * Chunk data encoding format for the shavar-proto list format.
 *
 * -*- magic methods -*-
 *
 * @method string getChunkNumber()
 * @method void setChunkNumber(\string $value)
 * @method \ChunkData\ChunkType getChunkType()
 * @method void setChunkType(\ChunkData\ChunkType $value)
 * @method \ChunkData\PrefixType getPrefixType()
 * @method void setPrefixType(\ChunkData\PrefixType $value)
 * @method string getHashes()
 * @method void setHashes(\string $value)
 * @method array getAddNumbers()
 * @method void appendAddNumbers(\string $value)
 */
class ChunkData extends \ProtocolBuffers\Message
{
  // @@protoc_insertion_point(traits:.ChunkData)
  
  /**
   * @var string $chunk_number
   * @tag 1
   * @label required
   * @type \ProtocolBuffers::TYPE_INT32
   **/
  protected $chunk_number;
  
  /**
   * @var \ChunkData\ChunkType $chunk_type
   * @tag 2
   * @label optional
   * @type \ProtocolBuffers::TYPE_ENUM
   * @see \ChunkData\ChunkType
   **/
  protected $chunk_type;
  
  /**
   * @var \ChunkData\PrefixType $prefix_type
   * @tag 3
   * @label optional
   * @type \ProtocolBuffers::TYPE_ENUM
   * @see \ChunkData\PrefixType
   **/
  protected $prefix_type;
  
  /**
   * Stores all SHA256 add or sub prefixes or full-length hashes. The number
   * of hashes can be inferred from the length of the hashes string and the
   * prefix type above.
   *
   * @var string $hashes
   * @tag 4
   * @label optional
   * @type \ProtocolBuffers::TYPE_BYTES
   **/
  protected $hashes;
  
  /**
   * Sub chunks also encode one add chunk number for every hash stored above.
   *
   * @var array $add_numbers
   * @tag 5
   * @label optional
   * @type \ProtocolBuffers::TYPE_INT32
   **/
  protected $add_numbers;
  
  
  // @@protoc_insertion_point(properties_scope:.ChunkData)

  // @@protoc_insertion_point(class_scope:.ChunkData)

  /**
   * get descriptor for protocol buffers
   * 
   * @return \ProtocolBuffersDescriptor
   */
  public static function getDescriptor()
  {
    static $descriptor;
    
    if (!isset($descriptor)) {
      $desc = new \ProtocolBuffers\DescriptorBuilder();
      $desc->addField(1, new \ProtocolBuffers\FieldDescriptor(array(
        "type"     => \ProtocolBuffers::TYPE_INT32,
        "name"     => "chunk_number",
        "required" => true,
        "optional" => false,
        "repeated" => false,
        "packable" => false,
        "default"  => null,
      )));
      $desc->addField(2, new \ProtocolBuffers\FieldDescriptor(array(
        "type"     => \ProtocolBuffers::TYPE_ENUM,
        "name"     => "chunk_type",
        "required" => false,
        "optional" => true,
        "repeated" => false,
        "packable" => false,
        "default"  => \ChunkData\ChunkType::ADD,
      )));
      $desc->addField(3, new \ProtocolBuffers\FieldDescriptor(array(
        "type"     => \ProtocolBuffers::TYPE_ENUM,
        "name"     => "prefix_type",
        "required" => false,
        "optional" => true,
        "repeated" => false,
        "packable" => false,
        "default"  => \ChunkData\PrefixType::PREFIX_4B,
      )));
      $desc->addField(4, new \ProtocolBuffers\FieldDescriptor(array(
        "type"     => \ProtocolBuffers::TYPE_BYTES,
        "name"     => "hashes",
        "required" => false,
        "optional" => true,
        "repeated" => false,
        "packable" => false,
        "default"  => null,
      )));
      $desc->addField(5, new \ProtocolBuffers\FieldDescriptor(array(
        "type"     => \ProtocolBuffers::TYPE_INT32,
        "name"     => "add_numbers",
        "required" => false,
        "optional" => false,
        "repeated" => true,
        "packable" => true,
        "default"  => null,
      )));
      // @@protoc_insertion_point(builder_scope:.ChunkData)

      $descriptor = $desc->build();
    }
    return $descriptor;
  }

}
