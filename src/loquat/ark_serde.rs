use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use serde::{Serializer, Deserializer, ser::Error, de::Error as DeError};

pub fn serialize<S, T: CanonicalSerialize>(data: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut bytes = vec![];
    data.serialize_compressed(&mut bytes).map_err(S::Error::custom)?;
    serializer.serialize_bytes(&bytes)
}

pub fn deserialize<'de, D, T: CanonicalDeserialize>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
    T::deserialize_compressed(&bytes[..]).map_err(D::Error::custom)
}

pub mod vec {
    use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
    use serde::{Serializer, Deserializer, ser::Error, de::Error as DeError, de::SeqAccess, ser::SerializeSeq};

    pub fn serialize<S, T>(data: &Vec<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: CanonicalSerialize,
    {
        let mut seq = serializer.serialize_seq(Some(data.len()))?;
        for item in data {
            let mut bytes = vec![];
            item.serialize_compressed(&mut bytes).map_err(S::Error::custom)?;
            seq.serialize_element(&bytes)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: CanonicalDeserialize,
    {
        struct VecVisitor<T> {
            _marker: std::marker::PhantomData<T>,
        }

        impl<'de, T: CanonicalDeserialize> serde::de::Visitor<'de> for VecVisitor<T> {
            type Value = Vec<T>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a sequence of byte vectors")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut vec = Vec::new();
                while let Some(bytes) = seq.next_element::<Vec<u8>>()? {
                    let item = T::deserialize_compressed(&bytes[..]).map_err(A::Error::custom)?;
                    vec.push(item);
                }
                Ok(vec)
            }
        }

        deserializer.deserialize_seq(VecVisitor { _marker: std::marker::PhantomData })
    }
}

pub mod vec_vec {
    use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
    use serde::{Serializer, Deserializer, ser::Error, de::Error as DeError, de::SeqAccess, ser::SerializeSeq};

    pub fn serialize<S, T>(data: &Vec<Vec<T>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: CanonicalSerialize,
    {
        let mut seq = serializer.serialize_seq(Some(data.len()))?;
        for inner_vec in data {
            let mut inner_bytes = Vec::new();
            for item in inner_vec {
                 item.serialize_compressed(&mut inner_bytes).map_err(S::Error::custom)?;
            }
            seq.serialize_element(&inner_bytes)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<Vec<Vec<T>>, D::Error>
    where
        D: Deserializer<'de>,
        T: CanonicalDeserialize,
    {
         struct VecVecVisitor<T> {
            _marker: std::marker::PhantomData<T>,
        }

        impl<'de, T: CanonicalDeserialize> serde::de::Visitor<'de> for VecVecVisitor<T> {
            type Value = Vec<Vec<T>>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a sequence of sequences of byte vectors")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut outer_vec = Vec::new();
                 while let Some(inner_bytes) = seq.next_element::<Vec<u8>>()? {
                    let mut inner_vec = Vec::new();
                    let mut cursor = std::io::Cursor::new(inner_bytes);
                    while (cursor.position() as usize) < cursor.get_ref().len() {
                        let item = T::deserialize_compressed(&mut cursor).map_err(A::Error::custom)?;
                        inner_vec.push(item);
                    }
                    outer_vec.push(inner_vec);
                }
                Ok(outer_vec)
            }
        }

        deserializer.deserialize_seq(VecVecVisitor {
            _marker: std::marker::PhantomData,
        })
    }
}