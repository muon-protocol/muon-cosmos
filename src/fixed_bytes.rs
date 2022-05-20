//use serde::{Deserialize, Serialize};
//use schemars::{
//    gen::SchemaGenerator,
//    schema::*,
//    JsonSchema,
//};

#[macro_export]
macro_rules! construct_fixed_bytes {
    ( $(#[$attr:meta])* $visibility:vis struct $name:ident ( $n_bytes:expr ); ) => {
        #[repr(C)]
        $(#[$attr])*
        $visibility struct $name (pub [u8; $n_bytes]);

        impl From<Vec<u8>> for $name {
            #[inline]
            fn from(v: Vec<u8>) -> Self {
                $name(array_ref!(v, 0, $n_bytes).clone())
            }
        }

		impl From<[u8; $n_bytes]> for $name {
			/// Constructs a bytes type from the given bytes array of fixed length.
			///
			/// # Note
			///
			/// The given bytes are interpreted in big endian order.
			#[inline]
			fn from(bytes: [u8; $n_bytes]) -> Self {
				$name(bytes)
			}
		}

		impl<'a> From<&'a [u8; $n_bytes]> for $name {
			/// Constructs a bytes type from the given reference
			/// to the bytes array of fixed length.
			///
			/// # Note
			///
			/// The given bytes are interpreted in big endian order.
			#[inline]
			fn from(bytes: &'a [u8; $n_bytes]) -> Self {
				$name(*bytes)
			}
		}

		impl<'a> From<&'a mut [u8; $n_bytes]> for $name {
			/// Constructs a bytes type from the given reference
			/// to the mutable bytes array of fixed length.
			///
			/// # Note
			///
			/// The given bytes are interpreted in big endian order.
			#[inline]
			fn from(bytes: &'a mut [u8; $n_bytes]) -> Self {
				$name(*bytes)
			}
		}

		impl From<$name> for [u8; $n_bytes] {
			#[inline]
			fn from(s: $name) -> Self {
				s.0
			}
		}

		impl AsRef<[u8]> for $name {
			#[inline]
			fn as_ref(&self) -> &[u8] {
				self.as_bytes()
			}
		}

		impl AsMut<[u8]> for $name {
			#[inline]
			fn as_mut(&mut self) -> &mut [u8] {
				self.as_bytes_mut()
			}
		}

		impl $name {
			/// Returns a new fixed bytes where all bits are set to the given byte.
			#[inline]
			pub const fn repeat_byte(byte: u8) -> $name {
				$name([byte; $n_bytes])
			}

			/// Returns a new zero-initialized fixed bytes.
			#[inline]
			pub const fn zero() -> $name {
				$name::repeat_byte(0u8)
			}

			/// Returns the size of this bytes in bytes.
			#[inline]
			pub const fn len_bytes() -> usize {
				$n_bytes
			}

			/// Extracts a byte slice containing the entire fixed bytes.
			#[inline]
			pub fn as_bytes(&self) -> &[u8] {
				&self.0
			}

			/// Extracts a mutable byte slice containing the entire fixed bytes.
			#[inline]
			pub fn as_bytes_mut(&mut self) -> &mut [u8] {
				&mut self.0
			}

			/// Extracts a reference to the byte array containing the entire fixed bytes.
			#[inline]
			pub const fn as_fixed_bytes(&self) -> &[u8; $n_bytes] {
				&self.0
			}

			/// Extracts a reference to the byte array containing the entire fixed bytes.
			#[inline]
			pub fn as_fixed_bytes_mut(&mut self) -> &mut [u8; $n_bytes] {
				&mut self.0
			}

			/// Returns the inner bytes array.
			#[inline]
			pub const fn to_fixed_bytes(self) -> [u8; $n_bytes] {
				self.0
			}

			/// Returns a constant raw pointer to the value.
			#[inline]
			pub fn as_ptr(&self) -> *const u8 {
				self.as_bytes().as_ptr()
			}

			/// Returns a mutable raw pointer to the value.
			#[inline]
			pub fn as_mut_ptr(&mut self) -> *mut u8 {
				self.as_bytes_mut().as_mut_ptr()
			}

			/// Assign the bytes from the byte slice `src` to `self`.
			///
			/// # Note
			///
			/// The given bytes are interpreted in big endian order.
			///
			/// # Panics
			///
			/// If the length of `src` and the number of bytes in `self` do not match.
			pub fn assign_from_slice(&mut self, src: &[u8]) {
				std::assert_eq!(src.len(), $n_bytes);
				self.as_bytes_mut().copy_from_slice(src);
			}

			/// Create a new fixed-bytes from the given slice `src`.
			///
			/// # Note
			///
			/// The given bytes are interpreted in big endian order.
			///
			/// # Panics
			///
			/// If the length of `src` and the number of bytes in `Self` do not match.
			pub fn from_slice(src: &[u8]) -> Self {
				std::assert_eq!(src.len(), $n_bytes);
				let mut ret = Self::zero();
				ret.assign_from_slice(src);
				ret
			}

			/// Returns `true` if no bits are set.
			#[inline]
			pub fn is_zero(&self) -> bool {
				self.as_bytes().iter().all(|&byte| byte == 0u8)
			}
		}

        impl std::default::Default for $name {
            #[inline]
            fn default() -> Self {
                Self::zero()
            }
        }

		impl std::fmt::Debug for $name {
			fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
				std::write!(f, "{:#x}", self)
			}
		}

		impl std::fmt::Display for $name {
			fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
				std::write!(f, "0x")?;
				for i in &self.0[0..2] {
					std::write!(f, "{:02x}", i)?;
				}
				std::write!(f, "…")?;
				for i in &self.0[$n_bytes - 2..$n_bytes] {
					std::write!(f, "{:02x}", i)?;
				}
				Ok(())
			}
		}

		impl std::fmt::LowerHex for $name {
			fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
				if f.alternate() {
					std::write!(f, "0x")?;
				}
				for i in &self.0[..] {
					std::write!(f, "{:02x}", i)?;
				}
				Ok(())
			}
		}

		impl std::fmt::UpperHex for $name {
			fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
				if f.alternate() {
					std::write!(f, "0X")?;
				}
				for i in &self.0[..] {
					std::write!(f, "{:02X}", i)?;
				}
				Ok(())
			}
		}

//		impl Serialize for $name {
//            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//                where
//                    S: Serializer,
//            {
//                serializer.serialize_bytes(&self.0)
//            }
//        }

        impl Serialize for $name {
			fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
			where
				S: Serializer,
			{
                hex::serde::serialize(&self.0, serializer)
			}
		}

		impl<'de> Deserialize<'de> for $name {
			fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
			where
				D: Deserializer<'de>,
			{
                let bytes = hex::serde::deserialize(deserializer)?;
                Ok($name(bytes))
			}
		}

//        / JsonSchema implementation
//        impl JsonSchema for $name {
//            no_ref_schema!();
//
//            fn schema_name() -> String {
//                format!("Array_size_{}_of_{}", $n_bytes, u8::schema_name())
//            }
//
//            fn json_schema(gen: &mut SchemaGenerator) -> Schema {
//                SchemaObject {
//                    instance_type: Some(InstanceType::Array.into()),
//                    array: Some(Box::new(ArrayValidation {
//                        items: Some(gen.subschema_for::<u8>().into()),
//                        max_items: Some($n_bytes),
//                        min_items: Some($n_bytes),
//                        ..Default::default()
//                    })),
//                    ..Default::default()
//                }
//                .into()
//            }
//        }

        /// PartialEq implementation
        impl PartialEq for $name {
            fn eq(&self, other: &$name) -> bool {
                self.0 == other.0
            }

            fn ne(&self, other: &$name) -> bool {
                self.0 != other.0
            }
        }

        /// Clone implementation
        impl Clone for $name {
            fn clone(&self) -> Self {
                $name (self.0)
            }
        }
    }
}
